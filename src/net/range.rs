use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, RwLock},
};

use super::Http;
use crate::{
    error::Result,
    io::{Meter, NullMeter, ReadAt, check_bounds},
};

/// Small reads are served from aligned blocks of this size.
const BLOCK: u64 = 256 * 1024;
/// How many blocks to keep.
const CACHE_BLOCKS: usize = 64;

/// A remote file read with HTTP range requests.
///
/// Large reads go straight to the network; small scattered reads (headers,
/// tables) are rounded to aligned blocks and cached.
pub struct HttpRangeSource {
    http: Arc<Http>,
    url: String,
    size: u64,
    context: String,
    cache: Mutex<VecDeque<(u64, Arc<Vec<u8>>)>>,
    meter: RwLock<Arc<dyn Meter>>,
}

impl HttpRangeSource {
    pub fn open(http: Arc<Http>, url: &str, context: &str) -> Result<Self> {
        let size = http.content_length(url, context)?;
        Ok(Self::with_size(http, url, size, context))
    }

    pub fn with_size(http: Arc<Http>, url: &str, size: u64, context: &str) -> Self {
        Self {
            http,
            url: url.to_owned(),
            size,
            context: context.to_owned(),
            cache: Mutex::new(VecDeque::new()),
            meter: RwLock::new(Arc::new(NullMeter)),
        }
    }

    /// Route byte counts of subsequent network reads to `meter`.
    pub fn set_meter(&self, meter: Arc<dyn Meter>) {
        *self.meter.write().expect("meter lock") = meter;
    }

    fn meter(&self) -> Arc<dyn Meter> {
        self.meter.read().expect("meter lock").clone()
    }

    fn block(&self, index: u64) -> Result<Arc<Vec<u8>>> {
        if let Some((_, data)) = self
            .cache
            .lock()
            .expect("cache lock")
            .iter()
            .find(|(i, _)| *i == index)
        {
            return Ok(data.clone());
        }
        let start = index * BLOCK;
        let len = BLOCK.min(self.size - start);
        let data = Arc::new(self.http.get_range(
            &self.url,
            start,
            len,
            &self.context,
            self.meter().as_ref(),
        )?);
        let mut cache = self.cache.lock().expect("cache lock");
        cache.push_front((index, data.clone()));
        cache.truncate(CACHE_BLOCKS);
        Ok(data)
    }
}

impl ReadAt for HttpRangeSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        check_bounds(&self.context, self.size, offset, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        if buf.len() as u64 >= BLOCK {
            let data = self.http.get_range(
                &self.url,
                offset,
                buf.len() as u64,
                &self.context,
                self.meter().as_ref(),
            )?;
            buf.copy_from_slice(&data);
            return Ok(());
        }
        let mut written = 0usize;
        while written < buf.len() {
            let position = offset + written as u64;
            let index = position / BLOCK;
            let block = self.block(index)?;
            let within = (position - index * BLOCK) as usize;
            let take = (block.len() - within).min(buf.len() - written);
            buf[written..written + take].copy_from_slice(&block[within..within + take]);
            written += take;
        }
        Ok(())
    }
}

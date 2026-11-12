//! A single-line text input with a cursor.

#[derive(Debug, Clone, Default)]
pub struct TextInput {
    value: String,
    /// Cursor position in characters.
    cursor: usize,
}

impl TextInput {
    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    pub fn clear(&mut self) {
        self.set("");
    }

    pub fn insert(&mut self, ch: char) {
        let at = self.byte_index(self.cursor);
        self.value.insert(at, ch);
        self.cursor += 1;
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
            let at = self.byte_index(self.cursor);
            self.value.remove(at);
        }
    }

    pub fn delete(&mut self) {
        if self.cursor < self.value.chars().count() {
            let at = self.byte_index(self.cursor);
            self.value.remove(at);
        }
    }

    /// Deletes the word before the cursor (Ctrl-W).
    pub fn delete_word(&mut self) {
        while self.cursor > 0 && self.char_before().is_some_and(|c| !c.is_alphanumeric()) {
            self.backspace();
        }
        while self.cursor > 0 && self.char_before().is_some_and(char::is_alphanumeric) {
            self.backspace();
        }
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.value.chars().count());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    pub fn at_end(&self) -> bool {
        self.cursor == self.value.chars().count()
    }

    fn char_before(&self) -> Option<char> {
        self.value.chars().nth(self.cursor.checked_sub(1)?)
    }

    fn byte_index(&self, chars: usize) -> usize {
        self.value
            .char_indices()
            .nth(chars)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::TextInput;

    #[test]
    fn edits_at_the_cursor() {
        let mut t = TextInput::default();
        for c in "afd.sys".chars() {
            t.insert(c);
        }
        t.home();
        t.insert('x');
        assert_eq!(t.value(), "xafd.sys");
        t.end();
        t.backspace();
        assert_eq!(t.value(), "xafd.sy");
        t.delete_word();
        assert_eq!(t.value(), "xafd.");
        t.delete_word();
        assert_eq!(t.value(), "");
    }
}

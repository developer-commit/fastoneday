# fastoneday

Windows 드라이버 CVE에 해당하는 패치 전후 드라이버 바이너리를 찾아 내려받고,
SHA-256으로 검증하는 작은 CLI입니다.

`fastoneday`는 MSRC에서 제품별 KB 쌍을 확인하고 Winbindex와 Microsoft Symbol
Server에서 드라이버를 찾습니다. Symbol Server에서 올바른 파일을 받지 못하면 Microsoft
Update Catalog로 전환하며, 필요한 경우 UUP 미디어에서 RTM 기준 파일을 구해 PSF
델타를 복원합니다.

> [!IMPORTANT]
> 완전한 다운로드·복구 기능에는 외부 `7z` 또는 `7zz` 실행 파일이 필요합니다.
> `msdelta` 디코더는 바이너리에 포함되어 있지만, MSU/CAB 및 ESD 압축 해제는 여전히
> 7-Zip을 사용합니다. 릴리스 바이너리만 받아서는 모든 복구 경로를 실행할 수 없습니다.

## 요구 사항

- 7-Zip (`7z` 또는 `7zz`)
- 소스에서 빌드할 경우 Rust 1.88 이상
- Microsoft 서비스에 접근할 수 있는 네트워크

macOS에서는 다음과 같이 설치할 수 있습니다.

```bash
brew install sevenzip
```

Debian/Ubuntu에서는 다음과 같이 설치할 수 있습니다.

```bash
sudo apt install 7zip
```

`7z`나 `7zz`가 PATH에 없다면 실행 파일의 전체 경로를 지정합니다.

```bash
export ONEDAY_7ZIP=/path/to/7z
```

Windows에서는 `7z.exe`의 전체 경로를 지정할 수 있습니다.

```powershell
$env:ONEDAY_7ZIP = 'C:\Program Files\7-Zip\7z.exe'
```

`info` 명령과 Symbol Server 직접 다운로드 경로는 `7z` 없이 동작할 수 있습니다. 하지만
Catalog fallback이 필요한지는 실행 전에 확정할 수 없으므로, `download` 명령을 사용할
때는 7-Zip을 미리 준비하는 것을 전제로 합니다.

## 릴리스 바이너리

현재 GitHub Release에서 제공하는 바이너리는 macOS 11 이상을 사용하는 Apple Silicon
(`arm64`) Mac 전용입니다. Intel Mac, Linux, Windows에서는 소스에서 별도로 빌드해야
합니다. 릴리스 바이너리에는 7-Zip이 포함되지 않습니다.

```bash
curl -L \
  https://github.com/developer-commit/fastoneday/releases/download/v0.1.0/fastoneday-v0.1.0-aarch64-apple-darwin \
  -o fastoneday
chmod +x fastoneday
./fastoneday --help
```

v0.1.0 바이너리의 SHA-256은 다음과 같습니다.

```text
a02aafbc23ec48f98b4162285e429e58a89b699274deea3eb6792909bb576a81
```

이 바이너리는 Apple의 공증을 받지 않았습니다. 운영체제 보안 정책으로 실행할 수 없는
환경에서는 소스에서 직접 빌드하십시오.

## 빌드

```bash
cargo build --release --locked
```

생성된 실행 파일은 `target/release/fastoneday`입니다.

## 사용법

먼저 CVE의 드라이버와 지원 제품, 패치 전후 KB를 확인합니다.

```bash
fastoneday info CVE-2022-37969
```

`info`가 출력한 정확한 제품명을 사용해 패치 전후 파일을 받습니다.

```bash
fastoneday download \
  CVE-2022-37969 \
  'Windows 11 version 21H2 for x64-based Systems' \
  ./output \
  --driver clfs.sys
```

결과는 다음 위치에 기록됩니다.

```text
output/
├── before/clfs.sys
└── after/clfs.sys
```

전체 옵션은 다음 명령으로 확인합니다.

```bash
fastoneday --help
```

## 복구와 캐시

Symbol Server의 파일이 없거나 Winbindex SHA-256과 일치하지 않으면 다음 복구 경로를
사용합니다.

```text
Microsoft Update Catalog MSU 다운로드
  → 7-Zip으로 MSU/CAB 압축 해제
  → 완성 드라이버 또는 PSF 탐색
  → 필요한 경우 Microsoft UUP CDN의 ESD 다운로드
  → 7-Zip으로 RTM 기준 드라이버 추출
  → 내장 msdelta 디코더로 PSF 적용
  → Winbindex SHA-256과 일치할 때만 결과 게시
```

다운로드한 MSU와 ESD는 기본적으로 `fastoneday` 실행 파일이 있는 디렉터리의
`fastoneday-cache/`에 보관되고 다음 실행에서 재사용됩니다. 숨겨진 폴더나 운영체제 임시
디렉터리를 기본 저장소로 사용하지 않습니다. Catalog MSU는 최대 4 GiB, UUP ESD는 최대
8 GiB까지 다운로드될 수 있습니다. CLI는 미디어 이름, 예상 크기, 캐시 경로, 10% 단위
다운로드 진행률과 캐시 재사용 여부를 표준 오류에 표시합니다.

캐시 위치는 다음 환경변수로 변경할 수 있습니다.

```bash
export ONEDAY_CATALOG_CACHE=/path/to/oneday-catalog-cache
```

실행 파일이 있는 디렉터리에 쓰기 권한이 없다면 위 환경변수로 쓰기 가능한 경로를 반드시
지정해야 합니다.

로컬에 보유한 RTM 기준 파일을 먼저 검색하게 하려면 다음 경로를 지정합니다.

```bash
export ONEDAY_CATALOG_BASE_ROOT=/path/to/windows-drivers
```

## 검증 원칙

- Catalog와 UUP 다운로드는 허용된 Microsoft 호스트만 사용합니다.
- MSU는 Catalog가 제공한 크기와 해시로 검증합니다.
- UUP ESD는 UUP metadata의 크기와 SHA-1으로 검증합니다.
- 복원된 최종 드라이버는 기존 Winbindex SHA-256과 정확히 일치할 때만 출력됩니다.
- 기존 결과 파일의 해시가 다르면 자동으로 덮어쓰지 않습니다.

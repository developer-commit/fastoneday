# fastoneday

CVE 번호 하나로 **패치 전/후 바이너리를 정확한 버전으로 받아 패치 디핑 환경을 만드는** 터미널 UI
도구입니다. Windows의 `.sys`·`.dll`·`.exe`는 물론 Office(Click-to-Run/Microsoft 365, MSI 기반
Office 2016)의 `.exe`·`.dll`까지 다룹니다.

- **외부 프로그램 불필요**: 7-Zip 같은 외부 실행 파일을 호출하지 않습니다.
  - 컨테이너(CAB, WIM/ESD, PSF/CIX, MSP(OLE), Click-to-Run 스트림)는 Rust로 직접 해석합니다.
  - 압축 코덱은 검증된 오픈소스를 소스째 함께 빌드합니다: libmspack(LZX), wimlib(LZMS·LZX·XPRESS).
    MSZIP은 Rust의 miniz_oxide를 씁니다.
- **MSDelta는 공식 구현 우선**: Windows에서는 Microsoft의 `UpdateCompression.dll`/`msdelta.dll`로
  delta를 적용하고, 그 외 OS에서는 함께 빌드한 Rust 디코더를 씁니다. 이 디코더는 최신
  `msdelta.dll`(10.0.26100.9974)을 역분석해 Microsoft 구현과 같은 결과를 내도록 보완한 것입니다.
- **단일 획득 경로**: Winbindex 같은 제3자 인덱스를 쓰지 않습니다. 해당 KB의 업데이트 패키지(또는
  Office 빌드)가 유일한 기준이며, 모든 결과물은 그 패키지에 Microsoft가 넣어 둔 해시로 검증됩니다.
- **TUI**: CVE 자동완성, 바이너리 자동 선택·자동완성, 단계별 진행률 표시.

## 빠른 시작

필요한 것: Rust 1.88 이상, C 컴파일러(macOS는 Xcode Command Line Tools, Linux는 gcc 또는 clang).
C 코덱은 `cargo build`가 자동으로 함께 컴파일합니다.

```bash
cargo build --release --locked
./target/release/fastoneday                 # TUI
./target/release/fastoneday CVE-2024-38193  # CVE를 채운 채로 시작
```

Windows용은 GNU 툴체인(MinGW-w64)으로 빌드합니다. wimlib이 GNU C 확장을 쓰기 때문에 MSVC는 지원하지
않습니다. macOS나 Linux에서 mingw-w64로 교차 빌드할 수도 있습니다.

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu   # Windows의 MSYS2 또는 교차 빌드
```

TUI에서는 보통 **CVE 입력 → Enter → Enter** 두 번이면 끝납니다.

1. CVE 칸에 `2024-38193`처럼 번호 일부나 `clfs`, `excel` 같은 제목 단어를 입력하면 최근 CVE와
   이전 기록에서 후보가 뜹니다(↑↓ 선택, Tab/→ 완성, Enter 조회).
2. 조회가 끝나면 **추천 제품 행(★)** 과 **추천 바이너리(★)** 가 이미 선택되어 있습니다. 추천
   바이너리는 MSRC 본문에 적힌 파일명, 구성요소 규칙(예: "Common Log File System" → `clfs.sys`),
   Office 보안 릴리스 노트의 앱 분류를 근거로 고르고, 수정 패키지에 실제로 들어 있는 파일 목록으로
   다시 확인합니다. 바이너리 칸에 타이핑하면 그 업데이트에 들어 있는 수천 개의 실행 파일 이름으로
   자동완성됩니다.
3. Enter를 누르면 진행 상황이 단계별로 표시되고, 완료되면 결과 폴더가 표시됩니다.

| 키 | 동작 |
|----|------|
| Enter | CVE 조회 / 가져오기 시작 |
| ↑ ↓ PgUp PgDn | 목록 이동 |
| Tab / → | 자동완성 (제안이 없으면 다음 칸으로) |
| Shift-Tab | 이전 칸 |
| Esc | 제안 닫기 · 실행 중 작업 취소 · CVE 칸으로 |
| Ctrl-W / Ctrl-U | 단어 삭제 / 입력 지우기 |
| F1 | 도움말 |
| Ctrl-C | 작업 취소 또는 종료 |

제품 목록의 `⚡`는 원격에서 수 초 만에 읽는 패키지(Windows 11 24H2 이상·Server 2025, Office
Click-to-Run), `⬇`는 패키지 전체 다운로드가 필요한 경우(이전 Windows, Office 2016 MSI)입니다.

### 스크립트용 비대화식 실행

TUI와 같은 기능을 비대화식으로도 쓸 수 있습니다(CI, 일괄 처리용).

```bash
fastoneday fetch CVE-2024-38193                    # 추천 제품·바이너리로 가져오기
fastoneday fetch CVE-2024-38193 --list             # 제품 행과 바이너리 후보만 출력
fastoneday fetch CVE-2026-118703 -p 2 -b excel.exe # 2번 제품 행, 바이너리 지정
```

옵션: `-w/--workspace DIR`, `--no-pdb`, `-h/--help`, `-V/--version`.

## 결과물

기본 작업 폴더는 현재 디렉터리의 `fastoneday-workspace/`이며 `-w` 또는 `FASTONEDAY_HOME`으로
바꿀 수 있습니다.

```text
fastoneday-workspace/
├── cases/CVE-2024-38193/afd.sys/windows-11-24h2-x64-security-update/
│   ├── before/afd.sys   before/afd.pdb      # 10.0.26100.1150 (KB5040435)
│   ├── after/afd.sys    after/afd.pdb       # 10.0.26100.1455 (KB5041571)
│   ├── manifest.json                         # 버전·해시·출처·검증 근거
│   └── README.txt
├── cache/        # 카탈로그 조회, 패키지 인덱스, 전체 다운로드가 필요한 패키지
└── history.json  # 최근 CVE (자동완성용)
```

`before/`와 `after/`를 BinDiff, Diaphora, Ghidra Version Tracking 등에 그대로 넣으면 됩니다.
Symbol Server에 PDB가 공개되어 있으면 함께 받습니다.

## 획득 경로

```text
CVE ──MSRC──▶ 제품별 (이전 KB → 수정 KB) 또는 Office 채널별 (이전 빌드 → 수정 빌드)
KB  ──Microsoft Update Catalog──▶ 패키지(.msu/.cab) [+ 24H2 이상은 checkpoint 패키지]
패키지 ──순수 Rust 해석──▶ 해당 파일의 payload: 전체 파일 | null delta | forward delta
payload ──▶ 정확한 바이너리
   전체 파일 / null delta : 그대로 전개
   forward delta          : (A) delta에 기록된 대상 PE 식별자(TimeDateStamp, 섹션 배치)로
                                Microsoft Symbol Server에서 원본을 받거나
                            (B) 기준 파일에 delta를 적용해 재구성
                                기준 = checkpoint 패키지의 같은 구성요소(24H2 이상)
                                     또는 릴리스(RTM) 설치 이미지의 같은 구성요소
                                엔진 = Windows: UpdateCompression.dll → msdelta.dll (System32)
                                       그 외 OS: 내장 Rust 디코더
   └─ 어느 쪽이든 패키지(delta)에 들어 있는 대상 해시(SHA-256/MD5)와 일치해야만 저장
```

- **Windows 11 24H2 이상 / Server 2025**: MSU가 압축되지 않은 WIM이라 HTTP Range로 필요한 부분만
  읽습니다. 4.5 GB짜리 누적 업데이트에서도 보통 20~30 MB만 내려받습니다.
- **이전 Windows(10, 11 23H2 이하, Server 2016~2022)**: CAB 안의 CAB 구조라 패키지 전체를 한 번
  내려받아(카탈로그 해시로 검증) 캐시한 뒤, 중첩 CAB을 디스크에 풀지 않고 제자리에서 읽습니다.
- **Office Click-to-Run**: Microsoft Learn의 *Office 보안 업데이트 릴리스 노트*로 CVE가 수정된 빌드와
  같은 채널의 직전 보안 빌드를 정하고, Office CDN의 스트림 인덱스(`stream.*.db`)를 해석해 해당
  파일 구간만 Range로 받습니다. 파일별 SHA-256으로 검증합니다. LTSC 채널은 보안 수정만 들어가
  diff가 깔끔하므로 우선 추천합니다.
- **Office 2016(MSI)**: 카탈로그 CAB → `.msp` → 내장 CAB에서 전체 파일을 꺼냅니다.

- **릴리스(RTM) 기준 이미지**: 기준이 RTM 빌드인 경우 해당 빌드(`20348.1`, `26100.1` 등)의
  설치 ESD를 Microsoft CDN에서 HTTP Range로 열어 필요한 구성요소 파일만 꺼냅니다(보통 수십 MB).
  ESD 위치를 찾는 데만 공개 UUP 인덱스(api.uupdump.net)를 쓰며, 그 응답은 신뢰하지 않습니다.
  WIM blob의 SHA-1과 업데이트 패키지의 대상 해시가 최종 판단 기준입니다. 이전 KB에서 바뀌지 않은
  파일(RTM 그대로인 파일)도 이 이미지에서 정확히 가져옵니다.
- **Symbol Server 재배포 충돌 감지**: Microsoft가 코드가 같은 파일을 버전만 올려 재배포하면 Symbol
  Server의 같은 키에 다른 빌드가 올라와 있을 수 있습니다(예: 10.0.20348.5756 키에 .5773). 해시가
  다르면 버리고 (B) 재구성으로 넘어갑니다.

- **MSDelta 엔진**: Windows에서는 Microsoft가 서비싱에 쓰는 `UpdateCompression.dll`의 `ApplyDeltaB`를
  우선 씁니다. 없으면 `msdelta.dll`을 쓰며, 두 DLL 모두 System32에서만 불러옵니다. 공식 엔진이 delta를
  거부하면 내장 디코더로 한 번 더 시도합니다. 어떤 엔진으로 만들었는지는 진행 로그와
  `manifest.json`에 남습니다. 비교 목적으로 `FASTONEDAY_DELTA_ENGINE=portable`을 주면 내장 디코더만
  씁니다.

추천 행에서 아직 검증된 바이너리를 만들 수 없으면(아래 제약 참고) 같은 아키텍처의 다른 `⚡` 행으로
자동으로 넘어가며, 그 사실을 진행 로그에 남깁니다. 사용자가 직접 고른 행은 바꾸지 않습니다.

## 제약 사항

- **패치 당일의 새 바이너리**: Microsoft가 Symbol Server에 올리기 전(보통 패치 후 며칠~2주)에는
  (B) 재구성으로 만듭니다.
  - Windows에서는 공식 엔진을, macOS/Linux에서는 내장 디코더를 씁니다. 내장 디코더는 실제 업데이트
    delta로 시험했고, Microsoft 엔진이 받아들이는 delta는 모두 Microsoft 해시와 일치했습니다.
    - Server 2022 누적 업데이트의 PA30 delta 997개: amd64·x86·WOW64·.NET 표본 1,000개 중
      Microsoft 엔진이 받아들이는 전부
    - Windows 11 24H2 checkpoint의 PA31 delta 978개: 980개 중 Microsoft 엔진이 받아들이는 전부
    - `ntoskrnl.exe`, `ntfs.sys`, `dxgkrnl.sys`, `win32kbase.sys`, `ci.dll`, `cng.sys`를 포함한
      대형 PE 17개
  - 그래도 모든 결과는 해시로 검증하며, 재현하지 못한 결과는 저장하지 않고 이유를 표시합니다. 그런
    경우 Windows에서 실행하거나 Symbol Server 공개 후 다시 받으면 됩니다.
- 릴리스 이미지 위치는 UUP 인덱스가 찾지 못하는 빌드(일부 클라이언트 전용 Insider/신규 분기)에서는
  쓸 수 없습니다. 서버 빌드(20348, 26100 등)는 같은 분기의 클라이언트 구성요소 기준으로도 쓰입니다.
- Microsoft Update Catalog는 오래된 일부 누적 업데이트를 내립니다. 카탈로그에 없는 KB는 더 최신
  제품 행을 고르면 됩니다.
- arm64 Office Click-to-Run, 분할 WIM, Quantum 압축 CAB은 지원하지 않습니다.

## 구조

계층마다 하나의 책임만 가지며, 아래 계층은 위 계층을 모릅니다.

```text
src/
├── domain/      순수 데이터: CVE id, 제품·패치 쌍, 바이너리 이름, 해시, 결과
├── io/          ReadAt(임의 접근) 소스: 파일, 메모리, 슬라이스, 커서, 취소·진행률 계약
├── net/         HTTP 클라이언트(재시도, Range, 이어받기), HTTP Range 소스
├── formats/     순수 파서 — cab/ wim/ delta/ cix(PSF 인덱스) pe msp c2r component
├── delta_engine/ MSDelta 적용 — native(Windows 공식 DLL), portable(내장 디코더)
├── sources/     원격 서비스 — msrc/ catalog/ symbols uup(릴리스 이미지 위치) office/(릴리스 노트, CDN)
├── packages/    패키지 → 통일된 payload 인덱스 (WIM MSU, CAB MSU, MSP, C2R)
├── acquire/     단일 획득 경로: 패키지 로더, materializer, 릴리스 기준(baseline), Windows/Office 흐름
├── detect/      CVE → 패치된 바이너리 순위 (텍스트 추출, 구성요소 규칙)
├── store/       캐시, 기록, 케이스 작업 폴더
├── app/         UI 독립 유스케이스, 제품 순위 정책, 워커 스레드·이벤트
├── tui/         상태(state), 입력, 자동완성, 화면(view/)
└── headless.rs  비대화식 실행
crates/codecs/   libmspack·wimlib C 코드를 빌드하고 안전한 Rust API로 감싸는 크레이트(FFI는 여기에만)
third_party/     함께 빌드되는 외부 소스: 출처, 버전, 해시, 라이선스는 third_party/README.md 참고
```

## 개발

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu   # Windows 전용 코드 확인
```

외부 소스는 모두 `third_party/`에 고정되어 있고 빌드 중에 네트워크를 쓰지 않습니다. 출처, 업스트림
해시, 가져온 파일, 갱신 절차는 [`third_party/README.md`](third_party/README.md)에 있습니다.

## 라이선스

fastoneday 코드는 MIT입니다. 빌드된 실행 파일에는 LGPL인 libmspack(LGPL-2.1)과 wimlib 해제기
(LGPL-2.1-or-later)가 정적으로 링크됩니다. 실행 파일을 배포한다면 LGPL 조건을 지켜야 합니다. 해당
소스를 제공하고 다시 링크할 수 있게 해야 하며, 저장소 전체 소스를 함께 제공하는 것이 가장 간단합니다.

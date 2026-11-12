# third_party — 함께 빌드되는 외부 소스

fastoneday가 직접 구현하지 않는 디코더의 소스를 여기에 고정해 두고 프로젝트와 함께 빌드합니다.
빌드 중에 네트워크에서 코드를 받지 않으며, 바이너리에 들어가는 외부 코드는 이 디렉터리에 있는 것이
전부입니다. 각 파일의 SHA-256은 `SHA256SUMS`에 있습니다.

```bash
cd third_party && shasum -a 256 -c SHA256SUMS
```

| 디렉터리 | 업스트림 | 버전 | 라이선스 | 용도 |
|----------|----------|------|----------|------|
| `libmspack/` | [kyz/libmspack](https://github.com/kyz/libmspack) | v1.12 | LGPL-2.1 | CAB 폴더의 LZX 해제 (cabextract와 같은 디코더) |
| `wimlib/` | [wimlib.net](https://wimlib.net) | 1.14.5 | LGPL-2.1-or-later (일부 MIT) | WIM/ESD 청크의 LZMS·LZX·XPRESS 해제 |
| `msdelta/` | [jlevere/msdelta](https://github.com/jlevere/msdelta) | `fb5ab888` + 로컬 수정 | MIT OR Apache-2.0 | Windows가 아닌 OS에서 MSDelta(PA19/PA30/PA31) 적용 |
| `lzms/` | 같은 저장소의 `crates/lzms` | `fb5ab888` | MIT OR Apache-2.0 | `msdelta`의 의존성. 테스트에서는 독립 LZMS 인코더로 사용 |

C 소스는 `crates/codecs`(`fastoneday-codecs`)가 `cc`로 컴파일해 정적으로 링크합니다. `unsafe` FFI는 그
크레이트 안에만 있습니다.

## libmspack

- 원본: <https://github.com/kyz/libmspack/archive/refs/tags/v1.12.tar.gz>
  - SHA-256 `e9941cbfdab991af2afdd16ac746d3e194012838d81c80ce14d6a61bc69f78ce`
  - 태그 객체 `21eea85d3dd0c9d9cd4e765ff256e96f26b0acf2`
- 가져온 파일: 저장소의 `libmspack/` 아래 `mspack/{lzxd.c, lzx.h, mspack.h, system.h, macros.h,
  readbits.h, readhuff.h}`, `COPYING.LIB`, `AUTHORS`. 내용은 수정하지 않았습니다.
- 가져오지 않은 것: CAB 파서(`cabd.c`)와 다른 포맷의 디코더. CAB 구조 해석은 fastoneday가 직접 하고,
  LZX 비트스트림 해제만 libmspack에 맡깁니다.
- 연결 코드: `crates/codecs/csrc/mspack_glue.c`. libmspack의 `mspack_system`을 구현해 입출력을 Rust
  콜백으로 넘깁니다. 그래서 로컬 파일, 중첩 CAB, HTTP Range 어느 쪽에서 오는 데이터든 임시 파일 없이
  해제됩니다.

## wimlib

- 원본: <https://wimlib.net/downloads/wimlib-1.14.5.tar.gz>
  - SHA-256 `84221a3abd5b91228f15f8e6065c335a336237b5738197b75bf419eea561a194`
- 가져온 파일: `src/{decompress, decompress_common, compress_common, cpu_features, lzms_common,
  lzms_decompress, lzx_common, lzx_decompress, xpress_decompress}.c`, `include/` 전체, `COPYING`,
  `COPYING.LGPL`, `COPYING.GPLv3`. 내용은 수정하지 않았습니다. `compress_common.c`는 해제기가 쓰는
  공용 허프만 테이블 함수 때문에 링크에 필요합니다.
- 가져오지 않은 것: libwim의 이미지 I/O, 마운트, 압축기, NTFS-3G 연동. NTFS-3G를 링크하지 않으므로
  `COPYING`에 적힌 이중 라이선스 중 LGPLv2.1+ 쪽을 선택할 수 있습니다.
- 연결 코드: `crates/codecs/csrc/wimlib_glue.c`(할당자, 1회 초기화)와
  `crates/codecs/csrc/wimlib-config/config.h`(해제기 빌드에 필요한 최소 설정).
- WIM의 청크 테이블과 solid 리소스 헤더는 fastoneday(`src/formats/wim/resource.rs`)가 wimlib의
  `resource.c`·`blob_table.c`와 같은 규칙으로 해석하고, 청크 하나하나의 해제만 wimlib에 맡깁니다.

## msdelta, lzms

- 원본: <https://github.com/jlevere/msdelta> 커밋 `fb5ab88843e854f3fd32d553984d8685ae643913`의
  `git archive`.
- 가져온 파일
  - `msdelta/`: `src/`(CLI인 `src/main.rs`와 테스트 스냅샷 `src/pa30/snapshots` 제외), `LICENSE-MIT`,
    `LICENSE-APACHE`, `README.md`, `TODO.md`, `docs/feature-atoms.tsv`(단위 테스트가 읽는 변환 등록표)
  - `lzms/`: `crates/lzms/src`와 라이선스 파일. 내용은 수정하지 않았습니다.
- Windows에서는 Microsoft의 `UpdateCompression.dll`/`msdelta.dll`이 우선 쓰이고, 이 디코더는 그 외
  OS용과 공식 엔진이 거부한 경우의 보조 수단입니다(`src/delta_engine`). 출력은 항상 업데이트 패키지의
  해시로 검증되므로 틀린 파일이 저장되지는 않습니다.

### msdelta 로컬 수정

`Cargo.toml`은 라이브러리 전용으로 다시 썼습니다. CLI·벤치·퍼징 타깃과 그 의존성을 빼고, `lzms`를
경로 의존성으로 연결하고, `publish = false`로 설정했습니다. 테스트 전용 `[dev-dependencies]`만
남겼습니다.

소스는 Microsoft 구현을 역분석해 고쳤습니다. 기준은 `msdelta.dll` 10.0.26100.9974(공개 PDB 사용)와
`UpdateCompression.dll` 10.0.26100.9711입니다. delta 적용은 원본에 PE 변환을 먼저 적용해 T(source)를
만들고, 거기서 LZX 복사와 리터럴로 대상을 만드는 구조입니다. 그래서 T(source)와 복사 rift가 Microsoft와
한 바이트라도 다르면 해시가 맞지 않습니다. 바꾼 것은 다음과 같습니다.

| 영역 | 파일 | 내용 |
|------|------|------|
| rift 조회 | `src/lzx/rift.rs` | 첫 항목보다 작은 값은 마지막 항목을 쓰는 `RiftTable::Map` 규칙 |
| amd64 명령 길이 | `src/pe/transform.rs` | 즉치값 크기(imm16, 3바이트, 피연산자 크기 접두) 수정 |
| PE 변환 | `src/pe/native.rs`(신규), `src/pe/atom.rs`, `src/pe/transform.rs` | `SectionHelper`·`DataDirectories` 해석과 MarkNonExe 표시 맵, imports/exports, `.pdata` 기반 DisasmAmd64, i386 상대 jmp/call, `.reloc`이 없는 i386의 추론 재배치 |
| .NET(CLI4) 흐름 | `src/pa30/mod.rs`, `src/pe/transform.rs` | CLI4 형식 지원, CLI 변환을 네이티브 흐름 위치에서 실행 |
| IL 토큰 | `src/pe/cli/disasm.rs`, `src/pe/cli/method.rs` | 생성자 특례 제거. 메서드 본문은 `GetMethodOffset`처럼 헤더와 IL만 다루고 EH 절은 제외. 마지막 MethodDef 행은 건너뜀 |
| 메타데이터 셀 | `src/pe/cli/metadata_transform.rs` | 짧은 열에 넘친 값은 하위 16비트만 저장 |
| 서명 blob | `src/pe/cli/signature.rs`(재작성), `src/pe/cli/metadata_transform.rs`, `src/pe/cli/schema.rs` | 네이티브 워커를 그대로 옮김. blob 종류별 처리와 오프셋 중복 제거, VOID/TYPEDBYREF·GENERICINST의 특이 동작 포함 |
| CLI 복사 rift | `src/pe/cli/rift.rs`(재작성) | `CompressionRiftTableFromCli(4)Map` 이식. 행 배치가 바뀐 표는 행마다 항목을 만들고, 열 폭 변경도 처리 |
| PA31 | `src/pa30/mod.rs` | LZMS+bsdiff를 T(source)에 적용. 원본이 비어 있으면 페이로드가 곧 대상 |
| E8 후처리 | `src/pe/transform.rs` | `PostProcessI386E8`처럼 헤더 플래그 bit 0만 보고 적용(.NET 이미지 포함). 끝 경계는 5바이트 |
| 진단 | `src/pe/cli/diagnostics.rs`(신규), `src/lib.rs`, `src/pa30/mod.rs` | `fuzzing` 기능에서만 켜지는 T(source)·복사 출처 추적. 기본 빌드에는 들어가지 않음 |

검증에는 Microsoft 엔진을 Wine에서 실행해 얻은 정답을 썼습니다. 대상 파일과 Microsoft가 만든
T(source)를 내장 디코더의 결과와 바이트 단위로 비교했습니다.

| 시험 표본 | 업스트림 원본 | 수정 후 |
|-----------|---------------|---------|
| Server 2022 PA30 1,000개 | 754 | 997 |
| Windows 11 24H2 PA31 980개 | 782 | 978 |
| 대형 PE 17개(`ntoskrnl.exe` 등) | 11 | 17 |

남은 PA30 3개와 PA31 2개는 Microsoft 엔진도 Win32 오류 13(ERROR_INVALID_DATA)으로 거부하는
표본입니다.
업스트림 단위 테스트는 274개가 통과합니다. 14개는 이 저장소에 포함하지 않은 업스트림 테스트 픽스처가
필요해 실패합니다.

## 갱신 절차

1. 새 업스트림 아카이브를 받아 해시를 기록합니다.
2. 위에 적힌 파일만 교체합니다. 연결 코드나 `build.rs`의 파일 목록이 바뀌면 함께 고칩니다.
   `msdelta/`는 로컬 수정이 있으므로 덮어쓰지 말고, 이전 업스트림과 새 업스트림의 차이를 현재
   소스에 병합합니다.
3. 이 문서와 `SHA256SUMS`를 갱신합니다.
4. `cargo test --workspace`를 실행하고, 실제 업데이트 패키지로 종단 간 확인을 합니다. 확인 내용은
   CAB-era MSU의 LZX, 24H2 MSU와 ESD의 LZMS, delta 재구성입니다.

## 라이선스 유의 사항

fastoneday 자체 코드는 MIT입니다. 다만 빌드된 실행 파일에는 LGPL인 libmspack과 wimlib이 정적으로
링크됩니다. 실행 파일을 배포한다면 LGPL 조건을 지켜야 합니다. 해당 라이브러리 소스를 제공하고,
받는 사람이 수정한 라이브러리로 다시 링크할 수 있게 해야 합니다. 가장 간단한 방법은 이 저장소 전체
소스를 함께 제공하는 것입니다(`cargo build`로 다시 빌드할 수 있습니다).

# Quant-Off Security Skills

<div align="center">

[English](README.md) | 한국어
</div>

이 저장소는 보안 리서치를 위한 [Claude Code](https://docs.claude.com/en/docs/claude-code) **플러그인 마켓플레이스**입니다. Claude Code가 보안의 측면에서 코드를 검증하고, Ghidra로 바이너리 산출물을 분석하고, 코드베이스를 감사하는 작업을 정확하고 반복 가능하게 수행하도록 방법론을 제공합니다.

## 왜 필요한가

보안 보장은 주장하기는 쉽지만 검증하기는 어렵습니다. 상수-시간 코드는 컴파일러에 의해 타이밍 공격으로 바뀔 수 있고, 키를 지우는 `memset`은 DSE(Dead-Store Elimination)로 삭제될 수 있으며, 기억에만 의존한 감사는 정작 중요한 비인가 허점(구멍) 하나를 놓치기 쉽습니다. 이 스킬들은 제로 트러스트 및 '증거를 우선한 워크플로 구조'를 코드화해서 보장을 가정이 아니라 증명으로 만들도록 합니다.

## 제공 플러그인

현 시점에서 이 저장소에 포함된 스킬들은 다음 표와 같습니다.

| 플러그인                                                         | 역할                                                                                                           |
|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| [`crypto-source-audit`](plugins/crypto-source-audit)         | 소스 수준 암호 감사 상수-시간 실행, 비밀 소거(zeroization), 상수-시간 비교, CSPRNG 사용, 사이드 채널(side-channel) 저항성 점검                   |
| [`binary-crypto-verify`](plugins/binary-crypto-verify)       | 리버스 엔지니어링 도구(Ghidra, objdump, radare2)로 상수-시간 로직과 소거가 컴파일러를 통과해 살아남았는지 검증(재도입된 분기 없음, dead-store로 삭제된 소거 없음) |
| [`codebase-security-audit`](plugins/codebase-security-audit) | 인젝션, 인증 및 인가, 시크릿(비밀값), 암호 오용, 메모리 안전성, 역직렬화, SSRF, 의존성 위험 전반의 제로 트러스트 감사 심각도순/증거 기반 결과 산출                   |

모든 플러그인은 서로 이어지도록 설계했다. `crypto-source-audit`으로 소스를 감사하고, `binary-crypto-verify`로 컴파일러가 그 보장을 보존했는지 확인하고, `codebase-security-audit`으로 나머지 전부를 훑어 구조적으로 검사합니다.

## 스킬의 동작 방식

각 스킬은 동일한 구조를 따릅니다. 그래서 결과물이 grep 결과 더미가 아니라 하나의 감사 보고서가 됩니다.

- **범위 명시** 각 스킬은 언제 자신을 써야 하고 언제 형제 스킬을 써야 하는지 밝힙니다. 질문에 맞는 방법론이 실행되도록 하기 위함입니다.
- **기각할 합리화** 각 스킬은 잘못된 결과나 누락을 낳는 지름길과, 그 대신 요구되는 조치를 먼저 제시합니다.
- **판정이 아닌 작업 목록** 도구와 grep 출력은 후보로만 취급합니다. 각 항목은 지목된 비밀값이나 신뢰할 수 없는 입력원까지 추적해야 보고할 수 있고, 추적이 불가능한 항목은 조용히 버리지 않고 기각으로 기록합니다.
- **증거 게이트** 결과에는 협상 불가능한 증거 요건과 확신도가 붙습니다. 주석이나 검토자의 주장만으로는 확신도를 낮추지 않습니다.
- **사각지대 명시** 각 스킬은 자신의 한계를 열거합니다. 결과가 비어 있다고 해서 안전하다는 뜻으로 읽히지 않도록 하기 위함입니다.
- **점진적 공개** `SKILL.md`는 짧게 유지하고, 현재 단계에 필요한 세부 내용만 `references/`로 연결합니다. `binary-crypto-verify`는 실제 동작하는 Ghidra 헤드리스 스크립트를 `scripts/`에 함께 배포합니다.

## 설치

당신의 Claude Code 환경에 다음 명령을 통해 마켓플레이스를 추가해주세요. 이후 원하는 플러그인을 설치할 수 있습니다.

```
/plugin marketplace add Quant-Off/skills
/plugin install crypto-source-audit@quant-security
/plugin install binary-crypto-verify@quant-security
/plugin install codebase-security-audit@quant-security
```

`quant-security`는 이 마켓플레이스의 이름입니다(`.claude-plugin/marketplace.json`에 정의되어 있음). 각 플러그인은 이 저장소의 `plugins/<이름>` 아래에 위치해 있습니다. 설치 관리는 다음과 같습니다.

```
/plugin list # 설치된 목록 확인
/plugin marketplace update # 업데이트 받기
/plugin disable <이름>@quant-security
```

개발용 환경의 경우 로컬 체크아웃을 마켓플레이스로 추가할 수도 있습니다.

```
/plugin marketplace add ./path/to/this-repo
```

## 사용

설치 시 요청이 스킬과 맞물릴 때 자동으로 활성화됩니다(예를 들어, "이 암호 코드의 상수-시간 문제를 감사해줘", "이 memset이 최적화로 사라지지 않았는지 바이너리에서 확인해줘"). 또는 다음과 같이 직접 호출할 수도 있습니다.

```
/crypto-source-audit
/binary-crypto-verify
/codebase-security-audit
```

`binary-crypto-verify`는 호스트에 Ghidra(`$GHIDRA_HOME`) 또는 `objdump`, `radare2`가 존재해야 합니다.

## 저장소 구조

```
루트/
├── .claude-plugin/marketplace.json # 마켓플레이스 매니페스트(저장소 루트)
├── plugins/
│   └── <플러그인이름>/
│       ├── .claude-plugin/plugin.json
│       ├── skills/<스킬이름>/
│       │   ├── SKILL.md            # 진입점, 500줄 이하
│       │   ├── references/         # 필요할 때 읽는 세부 문서
│       │   └── scripts/            # 선택 실행 보조 도구
│       └── README.md
├── CLAUDE.md # 에이전트 가이드
├── CONTRIBUTING_KR.md # 기여 안내
└── README_KR.md # 한글 문서(이 문서)
```

## 기여

플러그인 추가 방법, 검증 절차, 규칙은 [CONTRIBUTING_KR.md](CONTRIBUTING_KR.md)를 참고하세요. 이 저장소에서 동작하는 Claude Code는 [CLAUDE.md](CLAUDE.md)의 지침을 따릅니다. 모든 스킬은 기본적으로 제로 트러스트와 폐쇄형 대응 태세를 따라야 합니다. 가능하면 오프라인에서 동작하고, 코드나 시크릿을 외부로 유출하지 않으며, 모든 결과에 구체적 증거와 명확한 수정안을 덧붙여야 합니다.

## 라이선스

[MIT](LICENSE)

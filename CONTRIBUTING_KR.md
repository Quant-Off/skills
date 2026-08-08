# 기여 안내

<div align="center">

[English](CONTRIBUTING.md) | 한국어
</div>

Quant-Off Security Skills 마켓플레이스 개선에 참여해 주셔서 감사합니다. 이 문서는 플러그인을 추가하거나 변경하는 방법을 다룹니다.

## 기본 원칙

- 모든 스킬은 제로 트러스트와 폐쇄형 대응 태세를 따릅니다. 가능하면 오프라인에서 동작하고, 코드나 시크릿을 외부로 유출하지 않으며, 모든 결과에 구체적 증거와 명확한 수정안을 붙입니다.
- 스킬과 플러그인 이름은 사용자가 직접 입력하므로 kebab-case로 짓고 바꾸지 않습니다.
- 각 스킬은 하나의 명확한 역할만 맡고, 기능을 중복해서 만들기보다 형제 스킬을 서로 참조하도록 합니다.

## 스킬 템플릿

이 저장소의 보안 스킬은 하나의 구조를 공유합니다. 처음부터 새로 쓰기보다 기존 스킬을 복사해서 시작하고, 다음 요소를 유지하세요.

- 3인칭 `description`에 "Use when" 트리거 문구와 "Not for" 문구를 넣고, 제외되는 경우를 담당하는 형제 스킬로 안내합니다.
- `## When to Use`와 `## When NOT to Use`를 짝으로 둡니다.
- `## Rationalizations to Reject` 표에 잘못된 결과나 누락을 낳는 지름길, 그것이 왜 틀렸는지, 대신 요구되는 조치를 적습니다.
- 워크플로는 단계마다 번호를 매기고 각 단계의 종료 조건을 명시합니다.
- 트리아지 단계에서 grep이나 도구 출력을 판정이 아니라 작업 목록으로 다루고, 항목마다 판정을 글로 남기게 합니다. 추적이 불가능한 항목은 조용히 버리지 않고 기각으로 기록합니다.
- 증거 요건, 심각도 기준표, 코드 블록으로 감싼 보고 형식을 포함합니다.
- 번호를 매긴 `## Limitations`에 그 스킬의 사각지대를 적습니다.
- `## References`에는 실제 CWE, CVE, 논문을 인용합니다.

`SKILL.md`는 500줄 이하로 유지하고 세부 내용은 `references/`로 옮긴 뒤 라우팅 표로 연결해서, 현재 단계에 필요한 문서만 읽도록 합니다. 참조 파일은 1단계 깊이만 허용합니다. `SKILL.md`가 참조 파일을 링크하되, 참조 파일끼리 다시 연결하지는 않습니다. 실행 가능한 보조 도구는 `scripts/`에 두고 정확한 실행 명령을 `SKILL.md`에 적습니다.

## 새 플러그인 추가

1. `plugins/<이름>/.claude-plugin/plugin.json`을 만듭니다. 필수 필드는 `name` 하나이며, `description`, `version`, `author`, `license`, `keywords`도 함께 설정합니다.
2. `plugins/<이름>/skills/<스킬이름>/SKILL.md`에 위 템플릿을 따라 스킬을 추가합니다. `allowed-tools`를 설정하고, 감사 스킬은 읽기 전용(`Read Grep Glob Bash`)으로 유지합니다. `description`은 1,536자 제한을 넘지 않게 하고, 언제 이 스킬을 써야 하는지 드러나도록 트리거 친화적으로 작성합니다.
3. `.claude-plugin/marketplace.json`의 `plugins`에 플러그인을 등록합니다. `name`, `source: ./plugins/<이름>`, `description`, `version`, `author`, `license`, `category`, `keywords`를 넣습니다.
4. 간단한 `plugins/<이름>/README.md`를 추가합니다.
5. `README.md`와 `README_KR.md`의 플러그인 표를 함께 갱신합니다.

## 기존 플러그인 변경

- 스킬 동작이 바뀌면 `plugin.json`과 마켓플레이스 항목 양쪽의 `version`(semver)을 올립니다.
- 영문 문서와 한글 문서를 항상 같은 상태로 유지합니다.

## PR 전 검증

```bash
# JSON 유효성
find . -name '*.json' -path '*.claude-plugin*' -print -exec python3 -m json.tool {} /dev/null \;

# SKILL.md 프론트매터 존재 확인
find plugins -name SKILL.md -exec head -n1 {} \;

# SKILL.md 분량 확인(500줄 초과 시 분리)
find plugins -name SKILL.md -exec wc -l {} \;

# 선택 로컬 설치 후 스모크 테스트
/plugin marketplace add ./
/plugin install <플러그인이름>@quant-security
```

## 제출

`main`을 타겟으로 풀 리퀘스트를 열고, 해당 플러그인이나 스킬이 무엇을 왜 하는지 짧게 설명해주세요.

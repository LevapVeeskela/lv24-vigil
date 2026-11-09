# Vigil

**Аудит безопасности вашего кода — на вашей модели.**

Vigil — локальный аудитор безопасности в виде MCP-сервера и CLI. Он прогоняет
160+ детерминированных правил по репозиторию, а затем по желанию использует
модель, за которую вы уже платите: уточняет находки, смотрит рискованный код,
предлагает исправления и пишет модель угроз. Аккаунта Vigil, телеметрии и
обязательного Docker для обычного сканирования нет.

[![npm](https://img.shields.io/npm/v/lv24-vigil)](https://www.npmjs.com/package/lv24-vigil)
[![release](https://img.shields.io/github/v/release/LevapVeeskela/lv24-vigil)](https://github.com/LevapVeeskela/lv24-vigil/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![go](https://img.shields.io/badge/go-1.27-00ADD8)](https://go.dev/)

> **Статус: 0.2.0** (текущая версия в `latest` на npm). Детерминированный
> движок уже можно использовать. Вывод модели носит рекомендательный характер,
> покрытие правил растёт, и Vigil не заменяет пентест. Любая находка — это повод
> проверить, а не готовый приговор.

## Почему Vigil

- **Ваша модель, ваши ключи.** OpenAI, Anthropic, Gemini, OpenRouter, Groq,
  DeepSeek, Mistral, xAI, OpenCode Go, Ollama, LM Studio или любой OpenAI-совместимый
  endpoint. Без прокси, облачного аккаунта и телеметрии.
- **Сначала детерминизм.** Правила отрабатывают до вызова модели. Сбой
  провайдера не спрячет захардкоженный секрет или shell-инъекцию.
- **Встраивается в агента, которым вы уже пользуетесь.** Один MCP-сервер для
  OpenCode, Claude Code, Codex и Cursor. Агент может сканировать, объяснять,
  чинить и перепроверять, не выходя из диалога.
- **По умолчанию только чтение.** Сканирование не меняет исходники; оно пишет
  только свою историю в `.vigil/scans` или пользовательский кэш. `vigil fix
  --apply` записывает проверенный unified diff и никогда не коммитит; baseline и
  отчёт пишут только свои файлы. Секреты маскируются в выводе.
- **Маленький и переносимый.** Один статический бинарник на Go, стандартная
  библиотека плюс `gopkg.in/yaml.v3`, без CGO и без Docker для обычного скана.
- **Дружит с CI.** Markdown, JSON, SARIF и HTML. `--fail-on high` завершает
  процесс с кодом `2`, чтобы pull request мог остановиться на реальной находке.

## Как это работает

```text
 репозиторий
     |
     v
 +-----------------+     +--------------------------+     +-------------------+
 | обход + ignore  |---->| 160+ детерминированных   |---->| находки           |
 | размер + binary |     | правил: секреты, инъекции|     | severity evidence |
 +-----------------+     | crypto auth web config   |     +-------------------+
                         | CI deps                  |               |
                         +--------------------------+               v
                        +------------------------------------------------------+
                        | опционально, на вашей модели: triage, deep review,   |
                        | diff для фикса, STRIDE-модель угроз                  |
                        +------------------------------------------------------+
                                                                  |
                                                                  v
                        +------------------------------------------------------+
                        | baseline -> отчёт (md/json/sarif/html) -> история    |
                        |                                      -> MCP-ресурсы   |
                        +------------------------------------------------------+
```

Модель не подменяет детерминированные доказательства. Отсутствующая или
упавшая модель — это предупреждение, а не проваленный скан. Подробнее:
[docs/architecture.md](docs/architecture.md).

## Установка

```bash
npm i -g lv24-vigil@latest     # или зафиксировать версию: lv24-vigil@0.2.0
```

npm-пакет выбирает платформенный пакет (`@lv24/vigil-<os>-<cpu>`) при установке
и не запускает install-скрипты. Релизы публикуются через
[npm Trusted Publishing](docs/release.md) (OIDC) из GitHub Actions с аттестацией
происхождения (provenance); npm-токен в репозитории не хранится.

Другие варианты:

```bash
# Go 1.27+
go install github.com/levapveeskela/lv24-vigil/cmd/vigil@latest
```

Готовые бинарники и установщики публикуются в GitHub Releases. Для контейнеров
в репозитории есть distroless Dockerfile. Подробности:
[docs/install.md](docs/install.md).

## Быстрый старт за 60 секунд

```bash
cd your-repo

# Только детерминированные правила, без ключа и сети:
vigil scan --no-llm

# Добавить LLM-триаж с облачной моделью:
export OPENAI_API_KEY=sk-...
vigil scan

# Или оставить всё локально:
VIGIL_PROVIDER=ollama VIGIL_MODEL=qwen2.5-coder:14b vigil scan
```

Что дальше:

```bash
vigil status                         # провайдер, модель и источники настроек
vigil rules                          # каталог правил (источник истины)
vigil scan --format sarif --fail-on high
vigil review --base origin/main --format sarif --fail-on high
vigil fix VGL-XXXXXXXXXX             # показать предложенный unified diff
vigil fix VGL-XXXXXXXXXX --apply     # записать в рабочее дерево, без коммита
vigil threat-model                   # STRIDE-модель угроз, нужна модель
vigil report --format html > report.html
```

`vigil scan` без пути сканирует текущий каталог. ID находки берётся из
предыдущего скана или отчёта. Полный справочник команд:
[docs/cli.md](docs/cli.md).

## Использование из кодового агента (MCP)

Сервер запускается командой `vigil mcp` (stdio, JSON-RPC). Регистрация:

**OpenCode** — `opencode.json` в корне проекта (или
`~/.config/opencode/opencode.json`):

```json
{
  "mcp": {
    "vigil": {
      "type": "local",
      "command": ["npx", "-y", "lv24-vigil", "mcp"],
      "enabled": true
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add vigil -- npx -y lv24-vigil mcp
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.vigil]
command = "npx"
args = ["-y", "lv24-vigil", "mcp"]
```

**Cursor** — `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vigil": {
      "command": "npx",
      "args": ["-y", "lv24-vigil", "mcp"]
    }
  }
}
```

Дальше можно попросить агента: *«Просканируй этот репозиторий через Vigil и
объясни три главные находки»*. Настройка, инструменты, ресурсы и промпты:
[docs/mcp.md](docs/mcp.md).

## Провайдеры

Укажите `VIGIL_PROVIDER` и ключ провайдера — или дайте Vigil определить
провайдера по известному ключу. Явные переменные `VIGIL_*` важнее соглашений
провайдера.

| Провайдер | `VIGIL_PROVIDER` | Переменная ключа | Модель по умолчанию |
|---|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-4.1-mini` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` или `GOOGLE_API_KEY` | `gemini-2.5-flash` |
| OpenRouter | `openrouter` | `OPENROUTER_API_KEY` | `anthropic/claude-sonnet-4.5` |
| Groq | `groq` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` |
| DeepSeek | `deepseek` | `DEEPSEEK_API_KEY` | `deepseek-chat` |
| Mistral | `mistral` | `MISTRAL_API_KEY` | `mistral-large-latest` |
| xAI | `xai` | `XAI_API_KEY` | `grok-4-fast` |
| OpenCode Go | `opencode-go` | `OPENCODE_API_KEY` | `deepseek-v4.1-flash` |
| Ollama | `ollama` | не нужен | `qwen2.5-coder:14b` |
| LM Studio | `lmstudio` | не нужен | `local-model` |
| OpenAI-совместимый | `custom` | `VIGIL_API_KEY` | задайте `VIGIL_MODEL` |

Локальные модели:

```bash
VIGIL_PROVIDER=ollama VIGIL_MODEL=qwen2.5-coder:14b vigil scan
VIGIL_PROVIDER=lmstudio VIGIL_MODEL=local-model vigil scan
```

`OLLAMA_HOST` указывает на нестандартный Ollama. `VIGIL_BASE_URL` переопределяет
endpoint любого провайдера; для `custom` он обязателен. Полный справочник:
[docs/providers.md](docs/providers.md).

## Что проверяется

| Категория | Префикс | Правил | Что ищет |
|---|---|---:|---|
| Секреты | `VGL-SEC` | 24 | ключи облаков, токены, приватные ключи, строки подключения, утечки `.env` |
| Инъекции | `VGL-INJ` | 37 | SQL, shell, eval, XSS, десериализация, SSTI, prototype pollution |
| Криптография | `VGL-CRY` | 12 | слабые хэши/шифры, ECB, статические IV, плохая случайность, отключённый TLS, JWT `none` |
| Аутентификация | `VGL-AUTH` | 9 | непроверенные JWT, флаги cookie, CORS с credentials, CSRF, пароли по умолчанию |
| Web | `VGL-WEB` | 12 | SSRF, path traversal, open redirect, CORS, debug-endpoint, Host header |
| Конфигурация / IaC | `VGL-CFG` | 17 | Docker, Compose, Kubernetes, Terraform, nginx, закоммиченные env-файлы |
| CI | `VGL-CI` | 11 | незапиненные actions, `pull_request_target`, инъекции в скрипты, секреты в логах |
| Зависимости | `VGL-DEP` | 7 | отсутствие lockfile, wildcard-версии, git/HTTP-установки, отключённый TLS |

Примеры ID: `VGL-SEC-002` (critical, AWS secret key), `VGL-SEC-011` (critical,
приватный ключ), `VGL-INJ-001` (high, выполнение JS-кода), `VGL-INJ-019`
(critical, десериализация Java), `VGL-CRY-011` (critical, JWT `none`),
`VGL-AUTH-002` (critical, отключена проверка подписи JWT), `VGL-WEB-001` (high,
SSRF), `VGL-CFG-009` (high, Docker socket), `VGL-CI-002` (critical,
`pull_request_target` checkout), `VGL-DEP-006` (high, отключён TLS в npm).

Находки только от модели помечаются `VGL-AI-001` и имеют источник LLM.
Авторитетный список — команда `vigil rules`. Подробнее:
[docs/rules.md](docs/rules.md).

## Инструменты MCP

| Инструмент | Что делает | Пишет? |
|---|---|---|
| `vigil_scan` | Сканирует репозиторий или каталог | только история сканов |
| `vigil_review` | Проверяет только изменённые строки или переданный diff | только история сканов |
| `vigil_explain` | Объясняет одну находку в контексте | нет |
| `vigil_fix` | Предлагает unified diff; `apply=true` записывает его | только `apply=true` |
| `vigil_threat_model` | Генерирует STRIDE-модель угроз | нет |
| `vigil_status` | Статус провайдера, модели, движка и хранилища | нет |
| `vigil_rules` | Показывает каталог правил | нет |
| `vigil_baseline` | Смотрит или обновляет baseline подавлений | только файл baseline |
| `vigil_report` | Рендерит сохранённый скан в md/json/sarif/html | только при переданном `path` |
| `vigil_verify` | Перепроверяет, осталась ли находка | нет |
| `vigil_history` | Показывает историю сканов | нет |

Ресурсы: `vigil://status`, `vigil://rules`, `vigil://scan/last`,
`vigil://scan/<id>`. Промпты: `security_review`, `threat_model`, `fix_finding`.

Каждый инструмент возвращает полезный текстовый результат, даже если модель не
настроена: детерминированные находки не зависят от доступности LLM.

## CI

```bash
vigil review --base origin/main --format sarif --fail-on high > vigil.sarif
```

Загрузите результат через `github/codeql-action/upload-sarif` и не забудьте
`fetch-depth: 0`. В репозитории есть composite action `action.yml`; пример ниже
вызывает CLI напрямую, поэтому работает на любом runner.

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- run: npx -y lv24-vigil review --base origin/${{ github.base_ref }} --format sarif --fail-on high > vigil.sarif
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: vigil.sarif }
```

Pull request из форка не получает секреты репозитория; без ключа Vigil всё равно
прогоняет детерминированные правила. Полное руководство:
[docs/ci.md](docs/ci.md).

## Модель безопасности

- **Локальность.** Нет облака Vigil, телеметрии, аналитики и аккаунта.
- **По умолчанию только чтение.** Скан не пишет исходники; он пишет только
  историю сканов в `.vigil/scans` (или пользовательский кэш). Остальные пути
  записи: `vigil_fix` с `apply=true` (или `vigil fix --apply`), команда
  baseline, явно запрошенный файл отчёта и `vigil init`. Коммитов и staging нет.
- **Код уходит только туда, куда вы указали.** Детерминированный скан не делает
  сетевых вызовов. LLM-функции отправляют минимальный нужный контекст на
  настроенный endpoint. Если код не должен покидать машину — используйте
  локальную модель.
- **Секреты маскируются.** Найденные учётные данные редактируются в evidence,
  сниппетах и отчётах. Сырые значения секретов движок правил не печатает.
- **Сканируемый код — недоверенный.** Промпты обрамляют код как данные,
  вырезают управляющие символы и требуют игнорировать инструкции внутри кода.
  Вывод модели проверяется, прежде чем стать находкой или diff-ом.
- **Фиксы проверяются до записи.** Пути обязаны оставаться внутри репозитория
  (включая symlink/junction/hardlink), бинарные и symlink-патчи и правки `.git`
  отклоняются, счётчики строк в hunk-ах должны совпадать, а
  `git apply --check` выполняется до любой записи.

Детали и ограничения: [docs/security-model.md](docs/security-model.md).

## Сравнение

| | Strix (`usestrix/strix`) | Vigil | Облачный сканер |
|---|---|---|---|
| Что это | автономный пентест-агент | статический + LLM аудитор | управляемый сервис |
| Где работает | sandbox, нужен Docker | ваша машина или CI | облако вендора |
| Активно эксплуатирует цели | да | нет | по-разному |
| Встраивается в кодового агента через MCP | отдельная интеграция | из коробки | обычно нет |
| Код покидает машину | уходит вашей модели | только вашей модели, если включено | да |
| Для чего лучше | подтвердить эксплуатируемость | быстрые локальные повторяемые проверки | команды без локальной настройки |

Vigil и Strix дополняют друг друга: Vigil ловит дешёвые детерминированные
проблемы по ходу разработки, Strix подтверждает глубокие проблемы в
авторизованном sandbox. См. [docs/comparison.md](docs/comparison.md) и разбор
форка LV24 в [docs/lv24-security-analysis.md](docs/lv24-security-analysis.md).

## Планы

Не обязательства, а направление:

- шире покрытие языков и фреймворков для пакетов injection и auth;
- более точные data-flow правила без превращения Vigil в полноценный SAST;
- удобнее работать с baseline и подавлениями;
- больше рецептов для MCP-клиентов и редакторов;
- переводы документации помимо текущего английского набора.

## Документация

| Документ | Содержание |
|---|---|
| [docs/install.md](docs/install.md) | npm, Go, установщики, бинарники, контейнер |
| [docs/release.md](docs/release.md) | релизный конвейер, npm Trusted Publishing, проверка, повторные запуски |
| [docs/providers.md](docs/providers.md) | провайдеры, ключи, локальные модели, приоритет настроек |
| [docs/mcp.md](docs/mcp.md) | MCP-клиенты, инструменты, ресурсы, промпты |
| [docs/cli.md](docs/cli.md) | команды, флаги, коды выхода, форматы |
| [docs/rules.md](docs/rules.md) | семейства правил, примеры ID, baseline |
| [docs/ci.md](docs/ci.md) | GitHub Actions, SARIF, форки, baseline |
| [docs/security-model.md](docs/security-model.md) | сеть, маскирование, безопасность промптов, границы |
| [docs/architecture.md](docs/architecture.md) | пакеты, конвейер, решения |
| [docs/troubleshooting.md](docs/troubleshooting.md) | типовые ошибки и решения |
| [docs/comparison.md](docs/comparison.md) | Vigil, Strix и облачные сканеры |
| [docs/lv24-security-analysis.md](docs/lv24-security-analysis.md) | синхронизация Strix и форк LV24 |

Английская версия: [README.md](README.md). Изменения:
[CHANGELOG.md](CHANGELOG.md). Участие: [CONTRIBUTING.md](CONTRIBUTING.md).
Уязвимости: [SECURITY.md](SECURITY.md).

## Лицензия

Apache-2.0. См. [LICENSE](LICENSE).

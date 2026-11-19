# Trello workflow

Trello код сақтайтын жер емес. Код GitHub-та қалады, ал Trello тапсырманың күйін,
жауапты адамды, мерзімді және GitHub Pull Request сілтемесін көрсетеді.

## Тақта бағандары

`Backlog` → `To Do` → `In Progress` → `Code Review` → `Done`

## 20.11.2026 үшін дайын карточка

**Атауы:** `Secure file core: AES-GCM, storage API and tests`

**Сипаттамасы:**

> Client-side AES-256-GCM encryption, PBKDF2 key derivation, encrypted file
> storage, version checks, expiring access grants, REST API and automated tests.
> Plaintext, passwords and keys are never committed or sent to the server.

**Checklist:**

- [x] AES-GCM + PBKDF2 core
- [x] Encrypted `.scv` format
- [x] Storage and version validation
- [x] Expiring access grants
- [x] 20+ JUnit tests
- [x] GitHub Actions CI
- [ ] Teammate review
- [ ] Review comments fixed
- [ ] Merge after approval

**Карточка параметрлері:**

- Member: кодты жазған студент;
- Due date: `20.11.2026`;
- Label: `Code Review` немесе `Security`;
- List: `Code Review`;
- Attachment: осы feature branch-тің Pull Request URL-і.

## GitHub Power-Up арқылы қосу

1. Trello тақтасын ашыңыз.
2. Карточканы `Code Review` бағанына жылжытыңыз.
3. Карточкадан `Power-Ups` → `GitHub` таңдаңыз.
4. `Attach Pull Request` басып, репозиторийдегі ашық PR-ды таңдаңыз.
5. Командалас review аяқтаған соң ғана карточканы `Done` бағанына ауыстырыңыз.

Power-Up қолжетімсіз болса, PR сілтемесін кәдімгі Attachment немесе карточка
сипаттамасына қою жеткілікті. Кодты Trello-ға көшіріп салудың қажеті жоқ.

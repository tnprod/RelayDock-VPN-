# Участие в RelayDock

Сейчас особенно полезны небольшие воспроизводимые отчёты и исправления конкретных проблем.

## Ошибки и предложения

Укажите версию RelayDock, версию Windows и серверной ОС, выбранную схему, шаги и ожидаемый результат. Точный текст ошибки полезнее полного журнала. Перед отправкой уберите адреса своих серверов, имена пользователей, пароли, ключи, ссылки и QR-коды.

Для новой возможности сначала опишите сценарий в Issue: что вы хотите сделать и где мешает текущий интерфейс. Это поможет согласовать объём до большого изменения.

## Изменения кода

1. Создайте отдельную ветку и ограничьте PR одной задачей.
2. Установите `requirements-dev.txt` и выполните `python -m pytest tests -q`.
3. Для изменений интерфейса выполните `pnpm install --frozen-lockfile` и `pnpm run build` в `frontend/`. Приложите обезличенный снимок экрана, если меняется видимое поведение.
4. В PR объясните проблему, результат и выполненные проверки. Для изменений установки и маршрутизации укажите, что реально проверяли на VPS, а что осталось непроверенным.

В тестах используйте временные ключи и вымышленные данные. Не добавляйте рабочие конфигурации, приватные журналы и папку данных приложения. Не тестируйте изменения удалённой установки на чужих серверах.

## English

Small, focused contributions are welcome. Include a reproducible problem, expected behavior, and the checks you ran. Use generated test keys and synthetic data. Never attach live credentials, full connection links, QR codes, or the application data directory. Discuss substantial features in an issue before implementing them. Run the Python tests and, for frontend changes, the frontend build. State which remote installation changes were actually tested on a VPS.

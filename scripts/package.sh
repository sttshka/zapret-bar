#!/bin/bash
# Установочный образ ZapretBar для передачи другим: dist/ZapretBar-<версия>.dmg
# Приложение собирается сразу для Apple Silicon и Intel (нужен полный Xcode).
#   scripts/package.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

UNIVERSAL=1 scripts/build.sh

VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" Resources/Info.plist)
STAGE="$ROOT/build/dmg"
DMG="$ROOT/dist/ZapretBar-$VERSION.dmg"

echo "→ Готовлю образ"
rm -rf "$STAGE"
mkdir -p "$STAGE" "$ROOT/dist"
cp -R build/ZapretBar.app "$STAGE/"
ln -s /Applications "$STAGE/Applications"
cat > "$STAGE/Как открыть.txt" <<'EOF'
ZapretBar — обход замедления и блокировок прямо из строки меню macOS.

Установка
1. Перетащите ZapretBar в папку «Программы» (Applications).
2. Откройте его. Приложение не подписано сертификатом Apple, поэтому macOS
   при первом запуске его остановит. Тогда:
   Системные настройки → Конфиденциальность и безопасность → «Всё равно открыть».
   Если macOS пишет, что приложение «повреждено», выполните в Терминале:
     xattr -dr com.apple.quarantine /Applications/ZapretBar.app
3. В строке меню появится щит. Включите обход и нажмите «Подобрать» —
   приложение само найдёт способ, который работает у вашего провайдера.

Discord, X и сайты на Cloudflare
Нажмите «Разрешить» в меню: macOS один раз спросит пароль администратора,
и ZapretBar сможет показывать фильтру поддельное приветствие (как zapret на Windows).

Исходный код и лицензия (MIT): https://github.com/sttshka/zapret-bar
EOF

rm -f "$DMG"
hdiutil create -volname "ZapretBar $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDZO -ov "$DMG" >/dev/null
echo "Готово: $DMG ($(du -h "$DMG" | cut -f1))"

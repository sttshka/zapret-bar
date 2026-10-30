#!/bin/bash
# Сборка ZapretBar.app: tpws из zapret + Swift-приложение.
#   scripts/build.sh            — собрать в build/ZapretBar.app
#   scripts/build.sh --install  — собрать и положить в /Applications
#   UNIVERSAL=1 scripts/build.sh — приложение для Apple Silicon и Intel (нужен полный Xcode)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
ZAPRET="$ROOT/vendor/zapret"
APP="$ROOT/build/ZapretBar.app"
# Версия zapret, под которую написан patches/tpws-fake-macos.patch.
ZAPRET_REF=c4d0b1990129dce2b28095277173ee0d7702d304

if [ ! -d "$ZAPRET/tpws" ]; then
  echo "→ Скачиваю zapret ($ZAPRET_REF)"
  git clone https://github.com/bol-van/zapret.git "$ZAPRET"
  git -C "$ZAPRET" checkout -q "$ZAPRET_REF"
fi

# Наш патч: подмена ClientHello через /dev/bpf (на macOS нет divert-сокетов для nfqws).
if ! grep -q fake_send "$ZAPRET/tpws/tpws_conn.c"; then
  echo "→ Применяю patches/tpws-fake-macos.patch"
  git -C "$ZAPRET" apply "$ROOT/patches/tpws-fake-macos.patch"
fi

echo "→ Собираю tpws (universal: arm64 + x86_64)"
make -C "$ZAPRET/tpws" mac >/dev/null

echo "→ Собираю приложение"
SWIFT_ARGS=(-c release)
[ "${UNIVERSAL:-0}" = 1 ] && SWIFT_ARGS+=(--arch arm64 --arch x86_64)
swift build "${SWIFT_ARGS[@]}"
BIN="$(swift build "${SWIFT_ARGS[@]}" --show-bin-path)/ZapretBar"

echo "→ Упаковываю $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/ZapretBar"
cp "$ZAPRET/tpws/tpws" "$APP/Contents/Resources/tpws"
cp "$ROOT/scripts/diagnose.sh" "$APP/Contents/Resources/diagnose.sh"
mkdir -p "$APP/Contents/Resources/fake"
cp "$ZAPRET/files/fake/tls_clienthello_www_google_com.bin" "$APP/Contents/Resources/fake/"
cp "$ROOT/Resources/Info.plist" "$APP/Contents/Info.plist"
[ -f "$ROOT/Resources/AppIcon.icns" ] && cp "$ROOT/Resources/AppIcon.icns" "$APP/Contents/Resources/"

# Локальная подпись (ad-hoc): достаточно для запуска на своём Mac.
codesign --force --sign - "$APP/Contents/Resources/tpws"
codesign --force --sign - "$APP"

if [ "${1:-}" = "--install" ]; then
  echo "→ Устанавливаю в /Applications"
  # Штатный выход: приложение само вернёт настройки прокси.
  osascript -e 'quit app "ZapretBar"' 2>/dev/null && sleep 2 || true
  pkill -x ZapretBar 2>/dev/null || true
  rm -rf /Applications/ZapretBar.app
  cp -R "$APP" /Applications/
  open /Applications/ZapretBar.app
  echo "Готово: ZapretBar в строке меню."
else
  echo "Готово: $APP  (запуск: open \"$APP\")"
fi

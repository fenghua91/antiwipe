#!/system/bin/sh
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null)
  case "$exe" in
    /data/adb/modules/antiwipe/bin/guard|/data/adb/modules/antiwipe/bin/web) kill -9 "${p#/proc/}" 2>/dev/null;;
  esac
done
rm -f /data/adb/antiwipe/guard.pid /data/adb/antiwipe/keeper.lock
rm -rf /data/adb/antiwipe/run 2>/dev/null

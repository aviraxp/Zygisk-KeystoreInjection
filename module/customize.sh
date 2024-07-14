LIST="/data/adb/keystoreinjection/targetlist"

# Error on < Android 14.
if [ "$API" -lt 30 ]; then
    abort "- !!! You can't use this module on Android < 11"
fi

mkdir -p /data/adb/keystoreinjection
if [ ! -e "$LIST" ]; then
    echo "io.github.vvb2060.keyattestation" > "$LIST"
fi

ui_print "***********************************************************************"
ui_print "- Please move keybox to /data/adb/keystoreinjection/keybox.xml"
ui_print "- Please define target apps in /data/adb/keystoreinjection/targetlist"
ui_print "-     Format: one app per line"
ui_print "***********************************************************************"

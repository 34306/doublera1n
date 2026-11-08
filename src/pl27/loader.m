// Derived from Lycorine (https://github.com/hrtowii/lycorine-public) Lycorine/Bundled/Hooks/PreferenceLoader27/loader.m (LGPL-3.0, see NOTICE.md);
// rewritten for dualboot.
//
// Entry point of PreferenceLoader27 for the stock iOS 27 Settings app on OS B. Lycorine loads it into a
// relocated /var/jb Preferences.app; here ElleKit injects it into /Applications/Preferences.app through
// PreferenceLoader27.plist (Filter com.apple.Preferences).
//
// Kill switch: touch /var/jb/.pl27_disable (no Settings restart loop possible: Settings opens without it).
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <os/log.h>
#include <string.h>
#include <unistd.h>

extern void pl27_start(void);

static bool is_settings_app(void) {
    char path[PATH_MAX];
    uint32_t length = sizeof(path);
    if (_NSGetExecutablePath(path, &length) != 0) return false;
    return strcmp(path, "/Applications/Preferences.app/Preferences") == 0 ||
           strcmp(path, "/private/var/jb/Applications/Preferences.app/Preferences") == 0 ||
           strcmp(path, "/var/jb/Applications/Preferences.app/Preferences") == 0;
}

__attribute__((constructor)) static void pl27_load(void) {
    if (!is_settings_app()) return;
    if (access("/var/jb/.pl27_disable", F_OK) == 0) {
        os_log(OS_LOG_DEFAULT, "PreferenceLoader27: disabled by /var/jb/.pl27_disable");
        return;
    }
    // libprefs provides -[PSListController specifiersFromEntry:sourcePreferenceLoaderBundlePath:title:]
    // and +[PSSpecifier environmentPassesPreferenceLoaderFilter:]; PreferenceLoader.dylib links it.
    static const char *const candidates[] = {
        "/var/jb/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
        "/var/jb/usr/lib/TweakInject/PreferenceLoader.dylib",
        "/var/jb/usr/lib/libprefs.dylib",
    };
    for (unsigned i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (access(candidates[i], R_OK) != 0) continue;
        if (dlopen(candidates[i], RTLD_NOW | RTLD_GLOBAL) != NULL) {
            os_log(OS_LOG_DEFAULT, "PreferenceLoader27: libprefs ready (%{public}s)", candidates[i]);
            pl27_start();
            return;
        }
        os_log_error(OS_LOG_DEFAULT, "PreferenceLoader27: dlopen %{public}s failed: %{public}s",
                     candidates[i], dlerror());
    }
    os_log_error(OS_LOG_DEFAULT, "PreferenceLoader27: PreferenceLoader/libprefs not found, bridge not armed");
}

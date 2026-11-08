# PreferenceLoader27

Shows PreferenceLoader entries (`/var/jb/Library/PreferenceLoader/Preferences/*.plist`) as rows of the
iOS 27 Settings sidebar, which is SwiftUI (`SettingsApp.SettingsSidebarListState`) and no longer calls
`PSUIPrefsListController -specifiers`, so the stock PreferenceLoader never gets a chance to add them.

Source: https://github.com/hrtowii/lycorine-public, `Lycorine/Bundled/Hooks/PreferenceLoader27`
(the same bridge also appears in jakeajames/tr0y `Sources/PreferenceLoaderBridge` and in
0xjohnnydev/cryptsn0w `SBInject/sbinject_preferences_bridge.m`). License: LGPL-3.0, see `Support/LICENSE`.

Local changes (dualboot):
- `loader.m` rewritten: loads into stock `/Applications/Preferences.app` via ElleKit + `PreferenceLoader27.plist`,
  dlopens PreferenceLoader.dylib / libprefs, kill switch `/var/jb/.pl27_disable`.
- `bridge.m`: start function renamed `pl27_start`, os_log subsystem `dualboot.pl27`, log file
  `/var/mobile/Library/Logs/dualboot-pl27.log`, heap scan throttled to ~3/s while the sidebar state is absent.

Checked against iOS 27.2 (24B119) Preferences: `SettingsSidebarListState` has `_cachedSnapshot`
(`SettingsHost.ListContentSnapshot<…>?`) and `_selectionState`; `SettingsSidebarListItemIdentifier.connectedHeadphone`
carries `(identifier: String)`; `SettingsSidebarListSectionIdentifier.connectedHeadphones` has no payload.

Build: `./build.sh` → `payload/device/PreferenceLoader27.{dylib,plist}` (installed by `device/provision.sh`).

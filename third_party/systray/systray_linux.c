#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>

#ifdef USE_LEGACY_APPINDICATOR
#ifdef __has_include
#if __has_include(<libappindicator/app-indicator.h>)
#include <libappindicator/app-indicator.h>
#define HAVE_APPINDICATOR_HEADER 1
#endif
#endif
#define APPINDICATOR_PRIMARY "libappindicator3.so.1"
#define APPINDICATOR_FALLBACK "libappindicator3.so"
#else
#ifdef __has_include
#if __has_include(<libayatana-appindicator/app-indicator.h>)
#include <libayatana-appindicator/app-indicator.h>
#define HAVE_APPINDICATOR_HEADER 1
#endif
#endif
#define APPINDICATOR_PRIMARY "libayatana-appindicator3.so.1"
#define APPINDICATOR_FALLBACK "libayatana-appindicator3.so"
#endif

#ifdef __has_include
#if __has_include(<gtk/gtk.h>)
#include <gtk/gtk.h>
#define HAVE_GTK_HEADER 1
#endif
#endif

#ifndef HAVE_GTK_HEADER
typedef struct _GBytes GBytes;
typedef struct _GList {
	void *data;
	struct _GList *next;
	struct _GList *prev;
} GList;
typedef struct _GtkWidget GtkWidget;
typedef struct _GtkMenu GtkMenu;
typedef struct _GtkMenuShell GtkMenuShell;
typedef struct _GtkMenuItem GtkMenuItem;
typedef struct _GtkCheckMenuItem GtkCheckMenuItem;
typedef unsigned int guint;
typedef unsigned long gulong;
typedef int gboolean;
typedef char gchar;
typedef size_t gsize;
typedef void *gpointer;
typedef const void *gconstpointer;
typedef gboolean (*GSourceFunc)(gpointer);
typedef void (*GCallback)(void);
typedef struct _GClosure GClosure;
typedef void (*GClosureNotify)(gpointer, GClosure*);
typedef unsigned int GConnectFlags;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#endif

#ifndef G_CONNECT_SWAPPED
#define G_CONNECT_SWAPPED (1U << 1)
#endif

#ifndef HAVE_APPINDICATOR_HEADER
typedef enum {
	APP_INDICATOR_CATEGORY_APPLICATION_STATUS,
	APP_INDICATOR_CATEGORY_COMMUNICATIONS,
	APP_INDICATOR_CATEGORY_SYSTEM_SERVICES,
	APP_INDICATOR_CATEGORY_HARDWARE,
	APP_INDICATOR_CATEGORY_OTHER
} AppIndicatorCategory;

typedef enum {
	APP_INDICATOR_STATUS_PASSIVE,
	APP_INDICATOR_STATUS_ACTIVE,
	APP_INDICATOR_STATUS_ATTENTION
} AppIndicatorStatus;

typedef struct _AppIndicator AppIndicator;
#endif

#ifndef HAVE_GTK_HEADER
typedef struct _GObjectClass GObjectClass;
#endif

#include "systray.h"

#define ARRAY_COUNT(arr) (sizeof(arr) / sizeof((arr)[0]))

static AppIndicator *global_app_indicator;
static GtkWidget *global_tray_menu = NULL;
static GList *global_menu_items = NULL;
static char temp_file_name[PATH_MAX] = "";
static char loader_error[256] = "";

static void *lib_appindicator = NULL;
static void *lib_gtk = NULL;
static void *lib_gobject = NULL;
static void *lib_glib = NULL;

static void (*pgtk_init)(int*, char***);
static GtkWidget* (*pgtk_menu_new)(void);
static void (*pgtk_main)(void);
static void (*pgtk_main_quit)(void);
static AppIndicator* (*papp_indicator_new)(const gchar*, const gchar*, AppIndicatorCategory);
static void (*papp_indicator_set_status)(AppIndicator*, AppIndicatorStatus);
static void (*papp_indicator_set_menu)(AppIndicator*, GtkMenu*);
static void (*papp_indicator_set_icon_full)(AppIndicator*, const gchar*, const gchar*);
static void (*papp_indicator_set_attention_icon_full)(AppIndicator*, const gchar*, const gchar*);
static void (*papp_indicator_set_title)(AppIndicator*, const gchar*);
static void (*papp_indicator_set_label)(AppIndicator*, const gchar*, const gchar*);
static GtkWidget* (*pgtk_menu_item_new_with_label)(const gchar*);
static GtkWidget* (*pgtk_check_menu_item_new_with_label)(const gchar*);
static void (*pgtk_check_menu_item_set_active)(GtkCheckMenuItem*, gboolean);
static void (*pgtk_menu_item_set_label)(GtkMenuItem*, const gchar*);
static void (*pgtk_menu_shell_append)(GtkMenuShell*, GtkWidget*);
static GtkWidget* (*pgtk_menu_item_get_submenu)(GtkMenuItem*);
static void (*pgtk_menu_item_set_submenu)(GtkMenuItem*, GtkWidget*);
static GtkWidget* (*pgtk_separator_menu_item_new)(void);
static void (*pgtk_widget_set_sensitive)(GtkWidget*, gboolean);
static void (*pgtk_widget_show)(GtkWidget*);
static void (*pgtk_widget_hide)(GtkWidget*);
static gulong (*pg_signal_connect_data)(gpointer, const gchar*, GCallback, gpointer, GClosureNotify, GConnectFlags);
static void (*pg_signal_handler_block)(gpointer, gulong);
static void (*pg_signal_handler_unblock)(gpointer, gulong);
static GBytes* (*pg_bytes_new_static)(const void*, gsize);
static gconstpointer (*pg_bytes_get_data)(GBytes*, gsize*);
static void (*pg_bytes_unref)(GBytes*);
static guint (*pg_idle_add)(GSourceFunc, gpointer);

static void set_loader_error_dl(const char *action, const char *subject) {
	const char *err = dlerror();
	if (err == NULL) {
		err = "unknown error";
	}
	if (subject != NULL) {
		snprintf(loader_error, sizeof(loader_error), "%s(%s): %s", action, subject, err);
	} else {
		snprintf(loader_error, sizeof(loader_error), "%s: %s", action, err);
	}
}

static int library_is_banned(void *handle) {
	char origin[PATH_MAX];
	origin[0] = '\0';
	if (dlinfo(handle, RTLD_DI_ORIGIN, origin) != 0 || origin[0] == '\0') {
		struct link_map *map = NULL;
		if (dlinfo(handle, RTLD_DI_LINKMAP, &map) == 0 && map != NULL && map->l_name != NULL) {
			strncpy(origin, map->l_name, sizeof(origin) - 1);
			origin[sizeof(origin) - 1] = '\0';
		}
	}
	if (origin[0] == '\0') {
		return 0;
	}
	if (strstr(origin, "/snap/") != NULL) {
		snprintf(loader_error, sizeof(loader_error), "skipping library from %s (incompatible origin)", origin);
		return 1;
	}
	return 0;
}

static void *open_library(const char **names, size_t count) {
	for (size_t i = 0; i < count; i++) {
		dlerror();
		void *handle = dlopen(names[i], RTLD_LAZY | RTLD_GLOBAL);
		if (handle != NULL) {
			if (library_is_banned(handle)) {
				dlclose(handle);
				continue;
			}
			return handle;
		}
		set_loader_error_dl("dlopen", names[i]);
	}
	return NULL;
}

static int load_symbol(void *handle, const char *name, void **target) {
	const char *primary_err = NULL;
	dlerror();
	void *sym = NULL;
	if (handle != NULL) {
		sym = dlsym(handle, name);
		if (sym == NULL) {
			primary_err = dlerror();
		}
	}
	if (sym == NULL) {
		dlerror();
		sym = dlsym(RTLD_DEFAULT, name);
		if (sym == NULL) {
			const char *err = dlerror();
			if (err == NULL) {
				err = primary_err;
			}
			if (err == NULL) {
				err = "symbol not found";
			}
			if (name != NULL) {
				snprintf(loader_error, sizeof(loader_error), "dlsym(%s): %s", name, err);
			} else {
				snprintf(loader_error, sizeof(loader_error), "dlsym: %s", err);
			}
			return 0;
		}
	}
	*target = sym;
	return 1;
}

static int ensure_systray_runtime_loaded(void) {
	if (lib_appindicator != NULL) {
		return 1;
	}

	const char *gtk_candidates[] = {"libgtk-3.so.0", "libgtk-3.so"};
	lib_gtk = open_library(gtk_candidates, ARRAY_COUNT(gtk_candidates));
	if (lib_gtk == NULL) {
		return 0;
	}

	const char *gobject_candidates[] = {"libgobject-2.0.so.0", "libgobject-2.0.so"};
	lib_gobject = open_library(gobject_candidates, ARRAY_COUNT(gobject_candidates));
	if (lib_gobject == NULL) {
		return 0;
	}

	const char *glib_candidates[] = {"libglib-2.0.so.0", "libglib-2.0.so"};
	lib_glib = open_library(glib_candidates, ARRAY_COUNT(glib_candidates));
	if (lib_glib == NULL) {
		return 0;
	}

	const char *appindicator_candidates[] = {APPINDICATOR_PRIMARY, APPINDICATOR_FALLBACK};
	lib_appindicator = open_library(appindicator_candidates, ARRAY_COUNT(appindicator_candidates));
	if (lib_appindicator == NULL) {
		return 0;
	}

	if (!load_symbol(lib_gtk, "gtk_init", (void**)&pgtk_init)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_new", (void**)&pgtk_menu_new)) return 0;
	if (!load_symbol(lib_gtk, "gtk_main", (void**)&pgtk_main)) return 0;
	if (!load_symbol(lib_gtk, "gtk_main_quit", (void**)&pgtk_main_quit)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_new", (void**)&papp_indicator_new)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_status", (void**)&papp_indicator_set_status)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_menu", (void**)&papp_indicator_set_menu)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_icon_full", (void**)&papp_indicator_set_icon_full)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_attention_icon_full", (void**)&papp_indicator_set_attention_icon_full)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_title", (void**)&papp_indicator_set_title)) return 0;
	if (!load_symbol(lib_appindicator, "app_indicator_set_label", (void**)&papp_indicator_set_label)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_item_new_with_label", (void**)&pgtk_menu_item_new_with_label)) return 0;
	if (!load_symbol(lib_gtk, "gtk_check_menu_item_new_with_label", (void**)&pgtk_check_menu_item_new_with_label)) return 0;
	if (!load_symbol(lib_gtk, "gtk_check_menu_item_set_active", (void**)&pgtk_check_menu_item_set_active)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_item_set_label", (void**)&pgtk_menu_item_set_label)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_shell_append", (void**)&pgtk_menu_shell_append)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_item_get_submenu", (void**)&pgtk_menu_item_get_submenu)) return 0;
	if (!load_symbol(lib_gtk, "gtk_menu_item_set_submenu", (void**)&pgtk_menu_item_set_submenu)) return 0;
	if (!load_symbol(lib_gtk, "gtk_separator_menu_item_new", (void**)&pgtk_separator_menu_item_new)) return 0;
	if (!load_symbol(lib_gtk, "gtk_widget_set_sensitive", (void**)&pgtk_widget_set_sensitive)) return 0;
	if (!load_symbol(lib_gtk, "gtk_widget_show", (void**)&pgtk_widget_show)) return 0;
	if (!load_symbol(lib_gtk, "gtk_widget_hide", (void**)&pgtk_widget_hide)) return 0;
	if (!load_symbol(lib_gobject, "g_signal_connect_data", (void**)&pg_signal_connect_data)) return 0;
	if (!load_symbol(lib_gobject, "g_signal_handler_block", (void**)&pg_signal_handler_block)) return 0;
	if (!load_symbol(lib_gobject, "g_signal_handler_unblock", (void**)&pg_signal_handler_unblock)) return 0;
	if (!load_symbol(lib_glib, "g_bytes_new_static", (void**)&pg_bytes_new_static)) return 0;
	if (!load_symbol(lib_glib, "g_bytes_get_data", (void**)&pg_bytes_get_data)) return 0;
	if (!load_symbol(lib_glib, "g_bytes_unref", (void**)&pg_bytes_unref)) return 0;
	if (!load_symbol(lib_glib, "g_idle_add", (void**)&pg_idle_add)) return 0;

	return 1;
}

typedef struct {
	GtkWidget *menu_item;
	int menu_id;
	long signalHandlerId;
} MenuItemNode;

typedef struct {
	int menu_id;
	int parent_menu_id;
	char* title;
	char* tooltip;
	short disabled;
	short checked;
	short isCheckable;
} MenuItemInfo;

bool registerSystray(void) {
	if (!ensure_systray_runtime_loaded()) {
		systray_failed(loader_error);
		return false;
	}
	pgtk_init(0, NULL);
	global_app_indicator = papp_indicator_new("systray", "", APP_INDICATOR_CATEGORY_APPLICATION_STATUS);
	if (global_app_indicator == NULL) {
		snprintf(loader_error, sizeof(loader_error), "app_indicator_new returned NULL");
		systray_failed(loader_error);
		return false;
	}
	papp_indicator_set_status(global_app_indicator, APP_INDICATOR_STATUS_ACTIVE);
	global_tray_menu = pgtk_menu_new();
	papp_indicator_set_menu(global_app_indicator, (GtkMenu*)global_tray_menu);
	systray_ready();
	return true;
}

int nativeLoop(void) {
	pgtk_main();
	systray_on_exit();
	return 0;
}

void _unlink_temp_file() {
	if (strlen(temp_file_name) != 0) {
		int ret = unlink(temp_file_name);
		if (ret == -1) {
			printf("failed to remove temp icon file %s: %s\n", temp_file_name, strerror(errno));
		}
		temp_file_name[0] = '\0';
	}
}

// runs in main thread, should always return FALSE to prevent gtk to execute it again
gboolean do_set_icon(gpointer data) {
	_unlink_temp_file();
	char *tmpdir = getenv("TMPDIR");
	if (NULL == tmpdir) {
		tmpdir = "/tmp";
	}
	strncpy(temp_file_name, tmpdir, PATH_MAX-1);
	strncat(temp_file_name, "/systray_XXXXXX", PATH_MAX-1);
	temp_file_name[PATH_MAX-1] = '\0';

	GBytes* bytes = (GBytes*)data;
	int fd = mkstemp(temp_file_name);
	if (fd == -1) {
		printf("failed to create temp icon file %s: %s\n", temp_file_name, strerror(errno));
		return FALSE;
	}
	gsize size = 0;
	gconstpointer icon_data = pg_bytes_get_data(bytes, &size);
	ssize_t written = write(fd, icon_data, size);
	close(fd);
	if(written != (ssize_t)size) {
		printf("failed to write temp icon file %s: %s\n", temp_file_name, strerror(errno));
		return FALSE;
	}
	papp_indicator_set_icon_full(global_app_indicator, temp_file_name, "");
	papp_indicator_set_attention_icon_full(global_app_indicator, temp_file_name, "");
	pg_bytes_unref(bytes);
	return FALSE;
}

void _systray_menu_item_selected(int *id) {
	systray_menu_item_selected(*id);
}

GtkMenuItem* find_menu_by_id(int id) {
	GList* it;
	for(it = global_menu_items; it != NULL; it = it->next) {
		MenuItemNode* item = (MenuItemNode*)(it->data);
		if(item->menu_id == id) {
			return (GtkMenuItem*)(item->menu_item);
		}
	}
	return NULL;
}

// runs in main thread, should always return FALSE to prevent gtk to execute it again
gboolean do_add_or_update_menu_item(gpointer data) {
	MenuItemInfo *mii = (MenuItemInfo*)data;
	GList* it;
	for(it = global_menu_items; it != NULL; it = it->next) {
		MenuItemNode* item = (MenuItemNode*)(it->data);
		if(item->menu_id == mii->menu_id) {
			GtkWidget *menu_widget = item->menu_item;
			pgtk_menu_item_set_label((GtkMenuItem*)menu_widget, mii->title);
			if (mii->isCheckable) {
				// We need to block the "activate" event, to emulate the same behaviour as in the windows version
				// A Check/Uncheck does change the checkbox, but does not trigger the checkbox menuItem channel
				GtkCheckMenuItem *check_item = (GtkCheckMenuItem*)menu_widget;
				pg_signal_handler_block(check_item, item->signalHandlerId);
				pgtk_check_menu_item_set_active(check_item, mii->checked == 1);
				pg_signal_handler_unblock(check_item, item->signalHandlerId);
			}
			break;
		}
	}

	// menu id doesn't exist, add new item
	if(it == NULL) {
		GtkWidget *menu_item;
		if (mii->isCheckable) {
			menu_item = pgtk_check_menu_item_new_with_label(mii->title);
			pgtk_check_menu_item_set_active((GtkCheckMenuItem*)menu_item, mii->checked == 1);
		} else {
			menu_item = pgtk_menu_item_new_with_label(mii->title);
		}
		int *id = malloc(sizeof(int));
		*id = mii->menu_id;
		long signalHandlerId = pg_signal_connect_data(
			menu_item,
			"activate",
			(GCallback)_systray_menu_item_selected,
			id,
			NULL,
			(GConnectFlags)G_CONNECT_SWAPPED
		);

		if (mii->parent_menu_id == 0) {
			pgtk_menu_shell_append((GtkMenuShell*)global_tray_menu, menu_item);
		} else {
			GtkMenuItem* parentMenuItem = find_menu_by_id(mii->parent_menu_id);
			GtkWidget* parentMenu = pgtk_menu_item_get_submenu(parentMenuItem);

			if(parentMenu == NULL) {
				parentMenu = pgtk_menu_new();
				pgtk_menu_item_set_submenu(parentMenuItem, parentMenu);
			}

			pgtk_menu_shell_append((GtkMenuShell*)parentMenu, menu_item);
		}

		MenuItemNode* new_item = malloc(sizeof(MenuItemNode));
		new_item->menu_id = mii->menu_id;
		new_item->signalHandlerId = signalHandlerId;
		new_item->menu_item = menu_item;
		GList* new_node = malloc(sizeof(GList));
		new_node->data = new_item;
		new_node->next = global_menu_items;
		if(global_menu_items != NULL) {
			global_menu_items->prev = new_node;
		}
		global_menu_items = new_node;
		it = new_node;
	}
	GtkWidget* menu_item = ((MenuItemNode*)(it->data))->menu_item;
	pgtk_widget_set_sensitive(menu_item, mii->disabled != 1);
	pgtk_widget_show(menu_item);

	free(mii->title);
	free(mii->tooltip);
	free(mii);
	return FALSE;
}

gboolean do_add_separator(gpointer data) {
	GtkWidget *separator = pgtk_separator_menu_item_new();
	pgtk_menu_shell_append((GtkMenuShell*)global_tray_menu, separator);
	pgtk_widget_show(separator);
	return FALSE;
}

// runs in main thread, should always return FALSE to prevent gtk to execute it again
gboolean do_hide_menu_item(gpointer data) {
	MenuItemInfo *mii = (MenuItemInfo*)data;
	GList* it;
	for(it = global_menu_items; it != NULL; it = it->next) {
		MenuItemNode* item = (MenuItemNode*)(it->data);
		if(item->menu_id == mii->menu_id){
			pgtk_widget_hide(item->menu_item);
			break;
		}
	}
	return FALSE;
}

// runs in main thread, should always return FALSE to prevent gtk to execute it again
gboolean do_show_menu_item(gpointer data) {
	MenuItemInfo *mii = (MenuItemInfo*)data;
	GList* it;
	for(it = global_menu_items; it != NULL; it = it->next) {
		MenuItemNode* item = (MenuItemNode*)(it->data);
		if(item->menu_id == mii->menu_id){
			pgtk_widget_show(item->menu_item);
			break;
		}
	}
	return FALSE;
}

// runs in main thread, should always return FALSE to prevent gtk to execute it again
gboolean do_quit(gpointer data) {
	_unlink_temp_file();
	// app indicator doesn't provide a way to remove it, hide it as a workaround
	papp_indicator_set_status(global_app_indicator, APP_INDICATOR_STATUS_PASSIVE);
	pgtk_main_quit();
	return FALSE;
}

void setIcon(const char* iconBytes, int length, bool template) {
    if (pg_idle_add == NULL || pg_bytes_new_static == NULL) {
        snprintf(loader_error, sizeof(loader_error), "systray runtime not initialized");
        systray_failed(loader_error);
        return;
    }
	GBytes* bytes = pg_bytes_new_static(iconBytes, length);
	pg_idle_add(do_set_icon, bytes);
}

void setTitle(char* ctitle) {
	papp_indicator_set_title(global_app_indicator, ctitle);
	papp_indicator_set_label(global_app_indicator, ctitle, "");
	free(ctitle);
}

void setTooltip(char* ctooltip) {
	free(ctooltip);
}

void setMenuItemIcon(const char* iconBytes, int length, int menuId, bool template) {
}

void add_or_update_menu_item(int menu_id, int parent_menu_id, char* title, char* tooltip, short disabled, short checked, short isCheckable) {
	MenuItemInfo *mii = malloc(sizeof(MenuItemInfo));
	mii->menu_id = menu_id;
	mii->parent_menu_id = parent_menu_id;
	mii->title = title;
	mii->tooltip = tooltip;
	mii->disabled = disabled;
	mii->checked = checked;
	mii->isCheckable = isCheckable;
	pg_idle_add(do_add_or_update_menu_item, mii);
}

void add_separator(int menu_id) {
	MenuItemInfo *mii = malloc(sizeof(MenuItemInfo));
	mii->menu_id = menu_id;
	pg_idle_add(do_add_separator, mii);
}

void hide_menu_item(int menu_id) {
	MenuItemInfo *mii = malloc(sizeof(MenuItemInfo));
	mii->menu_id = menu_id;
	pg_idle_add(do_hide_menu_item, mii);
}

void show_menu_item(int menu_id) {
	MenuItemInfo *mii = malloc(sizeof(MenuItemInfo));
	mii->menu_id = menu_id;
	pg_idle_add(do_show_menu_item, mii);
}

void quit() {
	pg_idle_add(do_quit, NULL);
}

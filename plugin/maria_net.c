/* Loaded into mysqld only as an on/off mark. HTTP stays in the outside daemon.
   Build inside the 11.4 server tree:
   gcc -shared -fPIC -DMYSQL_DYNAMIC_PLUGIN -I/usr/include/mariadb/server \
     -o maria_net.so plugin/maria_net.c
*/

#include <mysql/plugin.h>

static int maria_net_init(void *p) {
  (void)p;
  return 0;
}

static int maria_net_deinit(void *p) {
  (void)p;
  return 0;
}

static struct st_mysql_daemon maria_net_daemon = {MYSQL_DAEMON_INTERFACE_VERSION};

maria_declare_plugin(maria_net){
    MYSQL_DAEMON_PLUGIN,
    &maria_net_daemon,
    "maria_net",
    "MariaDBBaaS",
    "On/off switch. The HTTP daemon runs outside mysqld.",
    PLUGIN_LICENSE_GPL,
    maria_net_init,
    maria_net_deinit,
    0x0001,
    NULL,
    NULL,
    "0.1",
    MariaDB_PLUGIN_MATURITY_STABLE,
} maria_declare_plugin_end;

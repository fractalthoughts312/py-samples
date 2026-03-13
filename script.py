#!/usr/bin/env python3
import os
import re
import logging
import argparse
import pymysql
from typing import Optional, Dict, Any
from ldap3 import Server, Connection, ALL

def _getenv(name: str, default: Optional[str] = None, *, required: bool = False) -> str:
    value = os.getenv(name, default)
    if required and (value is None or value == ""):
        raise RuntimeError(f"Missing required environment variable: {name}")
    return "" if value is None else value


def _getenv_int(name: str, default: int, *, required: bool = False) -> int:
    raw = os.getenv(name, None)
    if raw is None or raw == "":
        if required:
            raise RuntimeError(f"Missing required environment variable: {name}")
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise RuntimeError(f"Environment variable {name} must be an integer (got {raw!r})") from e


def _setup_logging() -> logging.Logger:
    log_level = _getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, log_level, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - [%(module)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


logger = _setup_logging()


CONFIG = {
    "ldap": {
        "server": _getenv("LDAP_SERVER", "ldap://ldap.example.local"),
        "user": _getenv("LDAP_USER", "svc_account"),
        "password": _getenv("LDAP_PASSWORD", required=True),
        "base_dn": _getenv("LDAP_BASE_DN", "OU=Users,DC=example,DC=local"),
        "search_filter": _getenv(
            "LDAP_SEARCH_FILTER",
            "(&(objectClass=user)(sAMAccountName=*)(extensionAttribute1=*))",
        ),
        "attributes": ["sAMAccountName", "extensionAttribute1", "telephoneNumber"],
    },
    "freepbx": {
        "sip_server": _getenv("SIP_SERVER", "pbx.example.local"),
        "sip_port": str(_getenv_int("SIP_PORT", 5060)),
        "graphql_url": _getenv("FREEPBX_GRAPHQL_URL", ""),
        "token_url": _getenv("FREEPBX_TOKEN_URL", ""),
        "client_id": _getenv("FREEPBX_CLIENT_ID", ""),
        "client_secret": _getenv("FREEPBX_CLIENT_SECRET", ""),
    },
    "database": {
        "host": _getenv("DB_HOST", "localhost"),
        "user": _getenv("DB_USER", "asterisk_admin"),
        "password": _getenv("DB_PASSWORD", required=True),
        "db": _getenv("DB_NAME", "asterisk"),
    },
    "tftp": {
        "config_dir": _getenv("TFTP_CONFIG_DIR", "/tftpboot/"),
        "config_template": """<<VOIP CONFIG FILE>>Version:2.0000000002
<SIP CONFIG MODULE>
--SIP Line List--  :
SIP1 Phone Number       :{extension}
SIP1 Register Addr      :{sipserver}
SIP1 Register Port      :{sipport}
SIP1 Register User      :{extension}
SIP1 Register Pswd      :{password}
SIP1 Enable Reg         :1
"""
    },
}

class LDAPManager:
    def __init__(self):
        self.server = Server(CONFIG['ldap']['server'], get_info=ALL)
        self.conn = None

    def connect(self) -> None:
        logger.info("Connecting to LDAP server...")
        try:
            self.conn = Connection(
                self.server,
                user=CONFIG['ldap']['user'],
                password=CONFIG['ldap']['password'],
                auto_bind=True
            )
            logger.info("Successfully connected to LDAP server")
        except Exception as e:
            logger.error(f"LDAP connection failed: {str(e)}")
            raise

    def disconnect(self) -> None:
        if self.conn and self.conn.bound:
            self.conn.unbind()
            logger.info("LDAP connection closed")

    def get_all_users(self) -> list:
        logger.info("Starting LDAP search for users...")
        if not self.conn or not self.conn.bound:
            self.connect()
        self.conn.search(
            search_base=CONFIG['ldap']['base_dn'],
            search_filter=CONFIG['ldap']['search_filter'],
            attributes=CONFIG['ldap']['attributes']
        )
        logger.debug(f"Found {len(self.conn.entries)} entries in LDAP")
        if not self.conn.entries:
            logger.warning("No users found in LDAP")
            return []
        logger.info("Successfully retrieved users from LDAP")
        return self.conn.entries

    @staticmethod
    def extract_mac_from_extension_attribute(attribute_value: str) -> Optional[str]:
        logger.debug(f"Parsing extensionAttribute1 for MAC address: {attribute_value}")
        if not attribute_value:
            logger.debug("No extensionAttribute1 value provided")
            return None
        mac_match = re.search(r"([0-9A-Fa-f]{2}[-:\.]?){5}[0-9A-Fa-f]{2}", attribute_value)
        if mac_match:
            raw_mac = mac_match.group(0)
            clean_mac = re.sub(r'[^0-9A-Fa-f]', '', raw_mac).lower()
            if len(clean_mac) == 12:
                logger.debug(f"Valid MAC address extracted: {clean_mac}")
                return clean_mac
            else:
                logger.debug(f"Invalid MAC length after cleaning: {clean_mac}")
        logger.debug("No valid MAC address found in extensionAttribute1")
        return None


class DatabaseManager:
    def __init__(self):
        self.connection = None

    def connect(self):
        logger.info("Connecting to Asterisk database...")
        try:
            self.connection = pymysql.connect(
                host=CONFIG['database']['host'],
                user=CONFIG['database']['user'],
                password=CONFIG['database']['password'],
                database=CONFIG['database']['db'],
                charset='utf8mb4',
                cursorclass=pymysql.cursors.DictCursor
            )
            logger.info("Successfully connected to Asterisk database")
        except pymysql.Error as e:
            logger.error(f"Database connection failed: {str(e)}")
            raise

    def disconnect(self):
        if self.connection:
            self.connection.close()
            logger.info("Database connection closed")

    def get_sip_password(self, extension: str) -> str:
        logger.debug(f"Fetching SIP password for extension {extension}")
        if not self.connection:
            self.connect()
        try:
            with self.connection.cursor() as cursor:
                sql = """
                SELECT data FROM sip
                WHERE id = %s AND keyword = 'secret'
                """
                cursor.execute(sql, (extension,))
                result = cursor.fetchone()
                if result:
                    logger.debug(f"Password found for extension {extension}")
                    return result['data']
                logger.warning(f"Password not found for extension {extension}")
                raise Exception(f"Password not found for extension {extension}")
        except pymysql.Error as e:
            logger.error(f"Database query failed: {str(e)}")
            raise


class ConfigGenerator:
    @staticmethod
    def generate_config(extension_data: Dict[str, Any]) -> str:
        logger.info("Generating config file from template...")
        try:
            config = CONFIG['tftp']['config_template'].format(**extension_data)
            logger.debug("Configuration successfully generated")
            return config
        except KeyError as e:
            logger.error(f"Missing required field in extension  {str(e)}")
            raise

    @staticmethod
    def save_config(mac_address: str, config_content: str, *, overwrite: bool, dry_run: bool) -> bool:
        logger.info(f"Saving config for device with MAC: {mac_address}")
        os.makedirs(CONFIG['tftp']['config_dir'], exist_ok=True)
        clean_mac = re.sub(r'[^0-9a-fA-F]', '', mac_address).lower()

        if len(clean_mac) != 12:
            logger.error(f"Invalid MAC address format: {mac_address}")
            raise ValueError(f"Invalid MAC address format: {mac_address}")

        filename = f"{clean_mac}.cfg"
        filepath = os.path.join(CONFIG['tftp']['config_dir'], filename)

        if os.path.exists(filepath) and not overwrite:
            logger.info(f"Config already exists, skipping: {filepath}")
            return False

        logger.debug(f"Writing configuration to {filepath} (overwrite={overwrite}, dry_run={dry_run})")
        try:
            if dry_run:
                logger.info(f"Dry-run: would write config to {filepath}")
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(config_content)
                logger.info(f"Successfully saved config to {filepath}")
            return True 
        except IOError as e:
            logger.error(f"Failed to save config file: {str(e)}")
            raise


class FreePBXManager:
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def get_extension_info(self, extension_number: str) -> Dict[str, Any]:
        logger.info(f"Fetching info for extension {extension_number}")
        try:
            password = self.db_manager.get_sip_password(extension_number)
            return {
                'extension': extension_number,
                'password': password,
                'sipserver': CONFIG['freepbx']['sip_server'],
                'sipport': CONFIG['freepbx']['sip_port']
            }
        except Exception as e:
            logger.error(f"Failed to get extension info: {str(e)}")
            raise


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate TFTP configs from LDAP users and Asterisk DB SIP secrets.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite config files if they already exist.")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files; only log what would happen.")
    parser.add_argument(
        "--tftp-dir",
        default=None,
        help="Override TFTP config directory (otherwise uses TFTP_CONFIG_DIR env var).",
    )
    return parser.parse_args()


def main():
    logger.info("Starting FreePBX configuration generator with DB access")
    args = _parse_args()

    if args.tftp_dir:
        CONFIG["tftp"]["config_dir"] = args.tftp_dir

    # Статистика
    stats = {
        'processed': 0,
        'created': 0,
        'skipped_exists': 0,
        'missing_mac': 0,
        'missing_extension': 0,
        'error_processing': 0
    }

    created_list = []
    skipped_mac_list = []
    skipped_ext_list = []
    error_list = []
    skipped_exists_list = []

    ldap_manager = None
    db_manager = None

    try:
        logger.debug("Initializing components...")
        ldap_manager = LDAPManager()
        db_manager = DatabaseManager()
        freepbx_manager = FreePBXManager(db_manager)
        config_generator = ConfigGenerator()

        logger.info("Connecting to services...")
        ldap_manager.connect()
        db_manager.connect()

        logger.info("Fetching users from LDAP...")
        users = ldap_manager.get_all_users()
        if not users:
            logger.warning("No users found to process")
            return

        logger.info(f"Processing {len(users)} users...")

        for user in users:
            username = getattr(user, 'sAMAccountName', None)
            if not username:
                logger.warning("User has no sAMAccountName, skipping entry")
                continue
            username = username.value
            stats['processed'] += 1

            logger.info(f"Processing user: {username}")

            try:
                ext_attr = getattr(user, 'extensionAttribute1', None)
                ext_attr_value = ext_attr.value if ext_attr else None
                mac_address = LDAPManager.extract_mac_from_extension_attribute(ext_attr_value)

                extension_number = getattr(user, 'telephoneNumber', None)
                ext_num_value = extension_number.value if extension_number else None

                if not mac_address:
                    logger.warning(f"No MAC address found for user {username}")
                    stats['missing_mac'] += 1
                    skipped_mac_list.append(username)
                    continue

                if not ext_num_value:
                    logger.warning(f"No extension number found for user {username}")
                    stats['missing_extension'] += 1
                    skipped_ext_list.append(username)
                    continue

                extension_data = freepbx_manager.get_extension_info(ext_num_value)
                config_content = config_generator.generate_config(extension_data)

                was_created = config_generator.save_config(
                    mac_address,
                    config_content,
                    overwrite=args.overwrite,
                    dry_run=args.dry_run,
                )

                if was_created:
                    stats['created'] += 1
                    created_list.append((username, ext_num_value, mac_address))
                else:
                    stats['skipped_exists'] += 1
                    skipped_exists_list.append((username, ext_num_value, mac_address))

            except Exception as e:
                logger.error(f"Error processing user {username}: {str(e)}")
                stats['error_processing'] += 1
                error_list.append(f"{username}: {str(e)}")
                continue

    except Exception as e:
        logger.critical(f"Fatal error occurred: {str(e)}", exc_info=True)
    finally:
        logger.info("Cleaning up resources...")
        try:
            if ldap_manager is not None:
                ldap_manager.disconnect()
        except Exception:
            pass
        try:
            if db_manager is not None:
                db_manager.disconnect()
        except Exception:
            pass

        logger.info("="*60)
        logger.info("🔧 FINAL REPORT")
        logger.info("="*60)
        logger.info(f"✅ Successfully created configs: {stats['created']}")
        for user, ext, mac in created_list:
            logger.info(f"    • {user} | Ext: {ext} | MAC: {mac}")

        logger.info(f"\n🟡 Skipped - already exists: {stats['skipped_exists']}")
        for user, ext, mac in skipped_exists_list:
            logger.info(f"    • {user} | Ext: {ext} | MAC: {mac}")

        logger.info(f"\n🔴 Skipped - missing MAC: {stats['missing_mac']}")
        for user in skipped_mac_list:
            logger.info(f"    • {user}")

        logger.info(f"\n🔴 Skipped - missing extension: {stats['missing_extension']}")
        for user in skipped_ext_list:
            logger.info(f"    • {user}")

        logger.info(f"\n❌ Errors during processing: {stats['error_processing']}")
        for err in error_list:
            logger.info(f"    • {err}")

        logger.info(f"\n📊 Total processed users: {stats['processed']}")
        logger.info("Configuration generation completed.")


if __name__ == "__main__":
    main()
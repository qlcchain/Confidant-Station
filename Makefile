include $(TOPDIR)/rules.mk

PKG_NAME:=pnr_server
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
QLC_SCRIPT_DIR:=
PNRLVERSION=$(shell $(TOPDIR)/feeds/qlc/scripts/getver.sh .)
PNRMVERSION=1
PNRTVERSION=0
PNRBUILDTIME=$(shell date "+%F %T")
	
include $(INCLUDE_DIR)/package.mk

define Package/pnr_server
	SECTION:=base
	CATEGORY:=QLC Apps
	TITLE:=pretty private messeger server
	DEPENDS:=+libpthread +libcurl +libnl-tiny +libsodium +libsqlite3 +libubox +libubus +libubus +libuci +libwebsockets +libpng +libqrencode
endef

define Package/pnr_server/description
	It's my first package demo.
endef

define Build/Prepare   #已修正
	echo "Here is Package/Prepare"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./source/* $(PKG_BUILD_DIR)/
	echo "$(PNRTVERSION).$(PNRMVERSION).$(PNRLVERSION)" > version
	sed -i -e "s/%t/$(PNRTVERSION)/" -e "s/%m/$(PNRMVERSION)/" -e "s/%l/$(PNRLVERSION)/" -e "s/%T/$(PNRBUILDTIME)/" $(PKG_BUILD_DIR)/inc/version.h
endef

define Package/pnr_server/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/pnrouter/mount-origin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pnr_server $(1)/bin/
#	$(INSTALL_DATA) $(TOOLCHAIN_DIR)/usr/lib/libsodium.so $(1)/lib/
	$(INSTALL_BIN) ./files/pnr_server $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/partition $(1)/etc/init.d/
	$(INSTALL_DATA) ./files/mount-origin/* $(1)/usr/pnrouter/mount-origin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/pnr_server ./ppr/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))

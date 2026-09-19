include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI Packet Flow Inspector & Debugger
LUCI_DEPENDS:=+luci-base +rpcd +nftables +ip-full
LUCI_PKGARCH:=all
PKG_LICENSE:=MIT
PKG_MAINTAINER:=cnjimmyshao

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature

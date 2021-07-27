
IMG_NAME=probely-onprem-agent
VERSION=1.1.0
IMG_VER=$(IMG_NAME)-$(VERSION)

.PHONY: default compress clean

default: build/$(IMG_VER).qcow2 build/$(IMG_VER).vmdk

build/$(IMG_VER).qcow2: alpine.pkr.hcl
	packer build .
	mv output-vm build
	mv build/$(IMG_NAME) build/$(IMG_VER).qcow2

build/$(IMG_VER).vmdk: build/$(IMG_VER).qcow2
	qemu-img convert -f qcow2 -O vmdk build/$(IMG_VER).qcow2 build/$(IMG_VER).vmdk

build/$(IMG_VER).vdi: build/$(IMG_VER).qcow2
	qemu-img convert -f qcow2 -O vdi build/$(IMG_VER).qcow2 build/$(IMG_VER).vdi

build/$(IMG_VER).vhd: build/$(IMG_VER).qcow2
	qemu-img convert -f qcow2 -O vpc build/$(IMG_VER).qcow2 build/$(IMG_VER).vhd

compress:
	test -f build/$(IMG_VER).vmdk && zip -9 build/$(IMG_VER).vmdk.zip build/$(IMG_VER).vmdk && rm build/$(IMG_VER).vmdk
	test -f build/$(IMG_VER).vdi && zip -9 build/$(IMG_VER).vdi.zip build/$(IMG_VER).vdi && rm build/$(IMG_VER).vdi
	test -f build/$(IMG_VER).vhd && zip -9 build/$(IMG_VER).vhd.zip build/$(IMG_VER).vhd && rm build/$(IMG_VER).vhd

clean:
	rm -rf build

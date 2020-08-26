clean:
	rm -rf build

build:
	mkdir build
	ppm --no-intro --compile="libsrc" --directory="build"

install:
	ppm --no-prompt --fix-conflict --install="build/net.intellivoid.accounts.saml.ppm"
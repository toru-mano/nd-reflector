.PHONY: all install clean

all: install

install: ../README.org

clean:
	rm README.org.org ndrd.8.txt

README.org.org: README.org ndrd.8.txt
	emacs README.org --batch -f org-org-export-to-org --kill

ndrd.8.txt: ndrd.8
	mandoc ndrd.8 | col -b | expand > ndrd.8.txt

../README.org: README.org.org
	install -m 644 README.org.org ../README.org

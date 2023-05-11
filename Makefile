VirusDetector: AntiVirus.c
	gcc -m32 -Wall AntiVirus.c -o VirusDetector

.PHONY: clean

clean:
	rm -f *.o VirusDetector
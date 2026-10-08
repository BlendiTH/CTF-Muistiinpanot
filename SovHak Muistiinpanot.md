## 1. Web & Directory Enumeration

### ffuf

```bash
# Peruskäyttö
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://LINKKITÄHÄN

# Tiedostopäätteet
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -e .php,.html,.txt,.bak

# Suodatus HTTP statuskoodien mukaan
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -mc 200,301,302,403

# Suodatus pois tietyn statuksen perusteella (esim toi 404)
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -fc 404

# Suodatus vastauksen koon (-fs) (kuten tunti esimerkissä silloin tehtiin) tai sanamäärän (-fw) perusteella
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -fs 1234
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -fw 42

# Rekursiivinen fuzzaus eli alihakemistojen löytäminen automaattisesti :D
ffuf -w wordlist.txt -u http://LINKKITÄHÄN -recursion -recursion-depth 2

# Parametri/arvofuzzaus (esim. GET-parametrin arvo)
ffuf -w wordlist.txt -u 'http://TARGET/page.php?id=FUZZ'

# POST-datan fuzzaus + evästeet/headerit
ffuf -w wordlist.txt -u http://TARGET/login -X POST \
  -d 'username=admin&password=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=xxxx'
```

- `-w` = sanalista **jonka jälkeen AINA tulee**  `-u` = kohde-URL
- `-mc` = match status codes, `-fc` = filter out codes, `-fs`/`-fw` = filter size/words
- `-t 50` nostaa threadsien määrää (nopeampi, mutta voi olla että ratelimitataan)
- `-o out.json -of json` tallentaa tulokset jatkokäsittelyy varten

### Selaimen DevTools ns. "tarkistuslista"

- **View Source / Ctrl+U**: kommentit, piilotetut lomakekentät (`type="hidden"`) ja vanhat endpointit
- **Network-välilehti**: kaikki XHR/fetch kutsut, API polut, headerit, cookiet, tokenit, jne.
- **Application/Storage**: localStorage, sessionStorage, cookiet (session-id, roolit, JWT)
- **Debugger/Sources**: JS tiedostot kokonaisuudessaan (tarkoituksena etsiä API-avaimia, kommentoitua koodia, reittejä)
- Tarkista `robots.txt`, `sitemap.xml`, `/.git/`, `/.env`, `/backup/`, `/admin/`
- Tarkista HTTP-vastausheaderit (`curl -I http://TARGET`), palvelin, tekniikka, evästeiden flagit

### IDOR / Broken Access Control
> Tästä kyselin tekoälyltä olisiko hyvä lisätä muistiinpanoihin..

- Vaihda URL:ssa tai parametrissa olevaa ID:tä toiseen arvoon ja katso näkeekö toisen käyttäjän datan: `GET /api/user/1042/profile` → kokeile `1041`, `1043`, `0`, negatiiviset arvot
- Tarkista toimiiko sama pyyntö ilman autentikointia (poista Authorization-header/cookie)
- Tarkista roolipohjainen pääsy: vaihda `role=user` → `role=admin` pyynnössä tai cookiessa
- Burp Repeater / curl toistuvaan manuaaliseen testaukseen:

```bash
curl -s http://TARGET/api/order/1001 -H 'Cookie: session=xxx'
```

### SQL Injection homma

```sql
-- Kirjautumisen ohittaminen esim. WHERE user='x' AND pass='y'
' OR 1=1 -- -
' OR '1'='1
admin'--
admin' #

-- UNION-based tiedon ulostulo (sarakemäärä selvitettävä ensin ORDER BY:lla)
' ORDER BY 3-- -
' UNION SELECT null,username,password FROM users-- -

-- Boolean/erroripohjainen tunnistus
' AND 1=1-- -   (tosi, sivu normaali)
' AND 1=2-- -   (epätosi, sivu muuttuu/virhe)
```

- `--` tai `#` kommentoi lopun kyselystä (MySQL: ` --  ` vaatii välilyönnin perään)
- Kannattaa ensin testata yhdellä lainausmerkillä `'` niin sitten saadaan syntaksivirhe joka myös paljastaa tarvittavan haavoittuvuuden

### Network Traffic Analysis (Wireshark tai tshark)
> Tästä voi olla hyötyä, ei kuitenkaan käytetty melkeinpä missään tehtävissä mutta ei voi ikinä tietää :DDDD

```bash
# Suodata HTTP-liikenne
tshark -r capture.pcap -Y http

# Pura HTTP-objektit (kuvat, tiedostot) PCAP:sta
tshark -r capture.pcap --export-objects http,out_dir/

# Hae tekstimuotoinen lippu kaikesta liikenteestä
strings capture.pcap | grep -i flag

# Seuraa TCP/HTTP-streamia (Wireshupadella: Follow > HTTP/TCP Stream)
tshark -r capture.pcap -z follow,tcp,ascii,0

# Suodata tietyn hostin/portin liikenne
tshark -r capture.pcap -Y 'ip.addr==10.0.0.5 && tcp.port==80'
```

---

## 2. Static Binary Analysis & Reverse Engineering 
> Perus hommat avattu vähän enemmän ja tarkemmin

### file / strings — ensimmäiset komennot aina

```bash
file ./binary                 # tiedostotyyppi & arkkitehtuuri 
strings ./binary               
strings -n 8 ./binary           # minimipituus x merkkiä (tässä esim. 8)
strings -a ./binary             # koko tiedosto, ei vain data-osiot
strings -e l ./binary           # 16-bit little-endian (UTF-16LE -merkkijonot, esim. Windows-binäärit)
strings -e b ./binary           # 16-bit big-endian
strings -t x ./binary           # näytä jonon offset heksana
strings ./binary | grep -i flag # suora flag-haku (aina voi yrittää LOL)
```

### UPX

```bash
strings ./binary | grep -i upx   # UPX-versiomerkintä binäärin lopussa
upx -d ./binary -o ./binary_unpacked   # pura pakkaus
chmod +x ./binary_unpacked
```

- Pakattu binääri näyttää Ghidrassa ja `strings`:issä hyvin vähän dataa (jolla olisi mitään merkitystä). Muistetaan purkaa aina ensin.

### Ghidra

1. **File > New Project** → **File > Import File** (valitse binääri, arkkitehtuuri yleensä tunnistuu automaattisesti)
2. Avaa binääri Code Browser -näkymään, hyväksy **Auto Analyze** oletusasetuksilla
3. **Symbol Tree > Functions > main** (tai `entry`, jos main ei stripattu pois) — kaksoisklikkaa
4. **Decompile-ikkuna** oikealla näyttää C-pseudokoodin — lue logiikka ylhäältä alas
5. Etsi `strcmp`, `strncmp`, `memcmp` -kutsuja → nämä usein vertaavat syötettä oikeaan flagiin/salasanaan
6. **Search > For Strings** (tai `Window > Defined Strings`) löytää kaikki binäärin merkkijonot kootusti
7. Oikea klikkaus muuttujaan → **Rename Variable** selkeyttää koodia itselle
8. **Right click function > Edit Function Signature**, tarkista paluuarvon tyyppi
9. Käytä **XREF** (Reference) -näkymää nähdäksesi mistä funktiota kutsutaan
10. Jos vakioarvo (esim. salasana) on koodattu suoraan, se näkyy decompilessa literaalina merkkijonona tai tavutaulukkona (tarkista myös heksamuodossa, jos XOR:attu)

---

## 3. Dynamic Analysis & Debugging

### ltrace, kirjastofunktiokutsujen jäljitys

```bash
ltrace ./binary                       # kaikki libc-kutsut (strcmp, malloc, printf...)
ltrace -f ./binary                     # seuraa myös fork()-lapsiprosesseja
ltrace -e strcmp ./binary              # vain tietty funktio
ltrace -S ./binary                     # näytä myös syscallit
ltrace -o trace.log ./binary arg1      # tallenna lokiin
```

- CTF-vinkki: jos ohjelma kysyy salasanaa, `ltrace` paljastaa usein suoraan `strcmp("syote", "oikea_flag")`-kutsun

### strace, järjestelmäkutsujen jäljitys

```bash
strace ./binary
strace -f ./binary                              # seuraa forkattuja prosesseja
strace -e trace=open,openat,read,write ./binary # rajaa tiettyihin syscalleihin
strace -o out.txt ./binary
```

### GDB komentolista (CGDB:LLÄ PAREMPI UI!!!)

```bash
gdb ./binary
gdb -q ./binary                 # hiljainen käynnistys (ei bannereita)
```

**Peruskulku**

```gdb
run                       # (r) käynnistä ohjelma
run arg1 arg2             # käynnistä argumenteilla
continue                  # (c) jatka breakpointista
next                      # (n) seuraava rivi, ei mene funktion sisään
step                      # (s) seuraava rivi, menee funktion sisään
nexti                     # (ni) seuraava assembly-käsky, ei mene call:iin
stepi                     # (si) seuraava assembly-käsky, menee call:iin
finish                    # aja nykyinen funktio loppuun asti, näyttää paluuarvon
```

**Breakpointit**

```gdb
break main                # breakpoint funktioon
break *0x0040117a         # breakpoint tarkkaan osoitteeseen
break *main+42            # breakpoint offsetilla
break file.c:25           # breakpoint rivinumeroon 
delete 1                  # poista breakpoint numero 1
condition 1 $rax==5       # ehdollinen breakpoint
```

**Rekisterit ja muisti**

```gdb
info registers            # (i r) kaikki rekisterit
p $rax                    # tulosta tietty rekisteri/paluuarvo
x/s $rsp                  # tulkitse muistiosoite merkkijonona
x/10x $rsp                # 10 sanaa heksana osoitteesta
x/4gx $rbp-0x10           # 4 kahdeksan tavun sanaa heksana
x/i $pc                   # tulkitse käsky disassemblynä
disassemble main           # koko funktion disassembly
disassemble $pc,+20        # 20 tavua eteenpäin nykyisestä käskystä
```

**Hyödyllistä**

```gdb
info functions             # listaa binäärin funktiot
layout asm                 # TUI-näkymä: assembly + rekisterit
layout regs                # TUI-näkymä: rekisterit näkyvissä jatkuvasti
watch variable_name        # pysähdy kun muuttujan arvo muuttuu
set $rax = 1               # muokkaa rekisterin arvoa lennossa (esim. ohita tarkistus)
```

> Vielä vähän semmonen confusion aihe, gdb ei ole lemppari ohjelma käyttää D:

---

## 4. Firmware & File Forensics

### binwalk, firmware-analyysi ja sen purku

```bash
binwalk firmware.bin                 # tunnista sisällön tyypit ja offsetit
binwalk -e firmware.bin              # pura löydetyt tiedostojärjestelmät/tiedostot
binwalk --dd='.*' firmware.bin        # pakota kaikkien tunnistettujen signatuurien purku
binwalk -Me firmware.bin              # (Matryoshka) rekursiivinen purku sisäkkäisille paketeille
```

- Tulokset puretaan kansioon `_firmware.bin.extracted/`
- Josta voi sitten etsiä sen jälkeen purusta flägiä: `grep -r flag _firmware.bin.extracted/`

### Tiedostotyypin ja metatiedon tunnistus

```bash
file mystery_file                 # tunnistaa tyypin magic-tavuista huolimatta päätteestä
xxd mystery_file | head -n 5      # tarkista magic bytes manuaalisesti
exiftool image.jpg                # kaikki metatieto (GPS, laite, muokkaushistoria, kommentit)
exiftool -all= image.jpg          # poista kaikki metatieto (ei flag-etsintään, vaan siivoukseen)
```

**Yleisiä magic bytes arvoja:**

| Tyyppi | Hex-alku |
| --- | --- |
| PNG | `89 50 4e 47` |
| JPEG | `ff d8 ff` |
| GIF | `47 49 46 38` |
| ZIP/APK/DOCX | `50 4b 03 04` |
| PDF | `25 50 44 46` |
| ELF | `7f 45 4c 46` |
| Windows EXE | `4d 5a` |

- Jos tiedostopääte on väärä/puuttuu pitää tarkista `file`-komennolla oikea tyyppi ja nimeä uudelleen oikealla päätteellä jos on esim. missannut oikean homman

---

## 5. Encoding, Ciphers & Cryptography

### Base64

```bash
echo -n 'teksti' | base64          # enkoodaus
echo 'dGVrc3Rp' | base64 -d         # dekoodaus
base64 -d file.b64 > output.bin     # tiedostosta
```

### Hex

```bash
echo -n 'teksti' | xxd -p           # teksti → hex
echo '74656b737469' | xxd -r -p     # hex → teksti
xxd file.bin | head                 # tiedoston hex-dumppi tarkasteluun
```

### ROT13 / Caesar

```bash
echo 'Uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m'   # ROT13 on oma käänteisensä (eli tosta tulisi Hello)
```

### XOR 

Tarkista omasta tehtävästä tarkemmin ohjeet / jne:
[H3-No Strings Attached](https://github.com/BlendiTH/Application-Hacking-and-Vulnerabilities/blob/main/H3-No%20Strings%20Attached.md#b-koodin-obfuskointi)

- CyberChef:n "Magic" operaatio tunnistaa automaattisesti suurimman osan yllä olevista :)!

---

## 6. TÄRKEÄT linkit

| Työkalu      | Käyttötarkoitus                                              | URL                               |
| ------------ | ------------------------------------------------------------ | --------------------------------- |
| CyberChef    | Enkoodausten/salausten purku, "Magic"-automaattitunnistus    | https://gchq.github.io/CyberChef/ |
| HackTricks   | Laaja metodologiawiki (web, binary, priv-esc, forensics)     | https://book.hacktricks.xyz/      |
| GTFOBins     | Unix-binäärit privilege escalationiin / rajoitusten kiertoon | https://gtfobins.github.io/       |
| dcode.fr     | Klassisten salausten (Caesar, Vigenère, ym.) tunnistus/purku | https://www.dcode.fr/             |
| CrackStation | Yleisten hashien (MD5/SHA1) käänteishaku                     | https://crackstation.net/         |


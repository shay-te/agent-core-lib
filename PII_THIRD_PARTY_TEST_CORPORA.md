# PII third-party test corpora — verbatim dump

This document is a research artifact for the UNA-2727 PII resilience
work. Operator's instruction: **pull every test input from every
open-source PII detection project on GitHub into a single document so
we can mine it for adversarial inputs and harden our regex set**.

Every string in this file is copied **verbatim** from the named
upstream test file. Source URL + path is given for each section so
the next maintainer can re-pull and diff against newer upstream
versions. Strings are listed exactly as they appear in the upstream
source (preserved quoting, separators, whitespace).

Buckets per section:

* **POSITIVE** — strings the upstream library's detector is asserted
  to match.
* **NEGATIVE** — strings the upstream library's detector is asserted
  to reject.

Where the upstream test file mixes the two without explicit labels,
the section reflects the upstream comment or assertion form.

**Status legend** (next to each section header):

* ✅ — exercised in our `test_pii_third_party_corpora.py` (lock
  asserts current behavior; agreement/disagreement is documented).
* ⚠️  — exercised partially in our bulletproof / adversarial suites;
  this file holds the complete upstream corpus.
* ⬜ — corpus collected here but not yet wired into a test. The
  operator's mandate is "we will solve this later" — these are the
  resilience-roadmap inputs.

---

## Source: Microsoft Presidio (MIT, ~4.5k stars, actively maintained)

Repo: <https://github.com/microsoft/presidio>
Recognizer tests live under `presidio-analyzer/tests/`.

### EMAIL ✅
Source file: `presidio-analyzer/tests/test_email_recognizer.py`

POSITIVE:
- `info@presidio.site`
- `my email address is info@presidio.site`
- `try one of these emails: info@presidio.site or anotherinfo@presidio.site`

NEGATIVE:
- `my email is info@presidio.`

### CREDIT CARD ✅
Source file: `presidio-analyzer/tests/test_credit_card_recognizer.py`

POSITIVE:
- `4012888888881881 4012-8888-8888-1881 4012 8888 8888 1881`
- `122000000000003`
- `my credit card: 122000000000003`
- `371449635398431`
- `5555555555554444`
- `5019717010103742`
- `30569309025904`
- `6011000400000000`
- `3528000700000000`
- `6759649826438453`
- `4111111111111111`
- `4917300800000000`
- `4484070000000000`

NEGATIVE (Luhn-invalid — Presidio rejects via checksum, we fire shape-only):
- `1748503543012`
- `4012-8888-8888-1882`
- `my credit card number is 4012-8888-8888-1882`
- `36168002586008`
- `my credit card number is 36168002586008`

### US SSN ✅
Source file: `presidio-analyzer/tests/test_us_ssn_recognizer.py`

POSITIVE:
- `078-051121 07805-1121`
- `078051121`
- `078-05-1123`
- `078.05.1123`
- `078 05 1123`
- `abc 078 05 1123 abc`

NEGATIVE:
- `0780511201`
- `078051120`
- `000000000`
- `666000000`
- `078-05-0000`
- `078 00 1123`
- `693-09.4444`

### PHONE ✅
Source file: `presidio-analyzer/tests/test_phone_recognizer.py`

POSITIVE:
- `My US number is (415) 555-0132, and my international one is +1 415 555 0132`
- `My Israeli number is 09-7625400`
- `_: (415)555-0132`
- `United States: (415)555-0132`
- `US: 415-555-0132`
- `_: +55 11 98456 5666`
- `Brazil: +55 11 98456 5666`
- `BR: +55 11 98456 5666`
- `My Japanese number is 090-1234-5678`
- `My CN number is 13812345678`
- `My US number is (415) 555-0132, and my international one is415-555-0132`
- `My US number is (415) 555-0132, and my international one is 91-415-555-0132`
- `My US number is (415) 555-0132, and my international one is +91 4155 550132`
- `My US number is (415) 555-0132, and my international one is +91 4155550132`
- `My US number is (415) 555-0132, and my international one is +44 (20) 7123 4567`
- `My US number is (415) 555-0132, and my international one is +55 11 98456 5666`
- `My US number is (415) 555-0132, and my international one is +49 30 1234567`
- `My US number is (415) 555-0132, and my international one is +39 06 678 4343`
- `My US number is (415) 555-0132, and my international one is +30 21 0 1234567`
- `My US number is (415) 555-0132, and my international one is +33 1 42 68 53 00`

### URL ✅
Source file: `presidio-analyzer/tests/test_url_recognizer.py`

POSITIVE:
- `https://www.microsoft.com/`
- `http://www.microsoft.com/`
- `http://www.microsoft.com`
- `http://microsoft.com`
- `http://microsoft.site`
- `http://microsoft.webcam`
- `http://microsoft.vlaanderen`
- `https://webhook.site/a8eedfd6-9d8a-44e0-b0fc-cc7d517db5dc?q=1&b=2`
- `https://www.microsoft.com/store/abc/`
- `microsoft.com`
- `my domains: microsoft.com google.co.il`
- `"https://microsoft.github.io/presidio/"`
- `'https://microsoft.github.io/presidio/'`

NEGATIVE:
- `www.microsoft`
- `http://microsoft`
- `'www.microsoft'`

### IP (IPv4 + IPv6) ✅
Source file: `presidio-analyzer/tests/test_ip_recognizer.py`

POSITIVE (IPv4):
- `microsoft.com 192.168.0.1`
- `localhost 127.0.0.1`
- `Broadcast 255.255.255.255`
- `Private 10.0.0.0`
- `Link-local 169.254.1.1`
- `Subnet 172.16.0.0`
- `Default 0.0.0.0`
- `(192.168.1.1)`
- `IP: 192.168.1.1.`
- `192.168.1.1,`
- `192.168.1.1.1`
- `192.168.1.0/24`
- `10.0.0.0/8`
- `0.0.0.0/0`
- `192.168.1.1/32`
- `Subnet: 192.168.1.0/24`
- `Route is 10.0.0.0/8.`
- `10.0.0.0/123`
- `192.168.2.1@eth0`

POSITIVE (IPv6):
- `microsoft.com 684D:1111:222:3333:4444:5555:6:77`
- `my ip: 684D:1111:222:3333:4444:5555:6:77`
- `2345:0425:2CA1:0000:0000:0567:5673:23b5`
- `2345:0425:2CA1::0567:5673:23b5`
- `2400:c401::5054:ff:fe1b:b031`
- `Use local ipv6 ::`
- `my ip: ::1`
- `connecting from ::1`
- `src=:: dst=::1`
- `fe80::1`
- `2001:db8::8a2e:370:7334`
- `2001:db8:85a3::8a2e:370`
- `2001:db8::1`
- `fe80::1%eth0`
- `Server IP: 2001:db8::1`
- `Connect to [2001:db8::1]:8080`
- `my ip is 2400:c401::5054:ff:fe1b:b031`
- `Gateway: fe80::1 on interface`
- `Visit http://[2001:db8::1]/path`
- `SSH to user@2001:db8::1`
- `::ffff:192.0.2.1`
- `::ffff:10.0.0.1`
- `::ffff:172.16.0.1`
- `::ffff:127.0.0.1`
- `::ffff:255.255.255.255`
- `::ffff:0.0.0.0`
- `::ffff:0:192.168.1.1`
- `::ffff:0000:10.0.0.1`
- `Mapped: ::ffff:192.168.1.1`
- `Connect to ::ffff:10.0.0.1 now`
- `[::ffff:192.168.1.1]:80`
- `::192.168.1.1`
- `::10.0.0.1`
- `2001:db8::192.168.1.1`
- `2001:db8:1::192.0.2.1`
- `64:ff9b::192.0.2.1`
- `2001:db8:85a3::8a2e:192.168.0.1`
- `0:0:0:0:0:FFFF:129.144.52.38`
- `2001:db8:0:0:0:0:192.168.1.1`
- `NAT64: 64:ff9b::198.51.100.1`
- `Tunnel to 2001:db8::10.0.0.1`
- `IPv4: 192.168.1.1, IPv6: 2001:db8::1`
- `Primary: 10.0.0.1, Secondary: 172.16.0.1`
- `IPs: 192.168.1.1, 10.0.0.1, 2001:db8::1`
- `'2001:db8::1'`
- `[2001:db8::1]`
- `Server IP: 2400:c401::5054:ff:fe1b:b031.`
- `2001:db8::1.`
- `Unspecified ::`
- `Loopback ::1`
- `Multicast ff02::1`
- `2001:db8::/32`
- `fe80::/10`
- `::1/128`
- `fe80::1%eth0/64`
- `2001:db8::%eth0/128`
- `::/0`
- `::/128`
- `::ffff:192.168.1.0/96`
- `64:ff9b::192.0.2.0/96`
- `Prefix: 2001:db8::/32`
- `Use 2001:db8::/32.`
- `2001:db8::/9999`

NEGATIVE:
- `my ip: 192.168.0`
- `684D:1111:222:3333:4444:5555:77`
- `fe80::1text`
- `text2001:db8::1`
- `MAC address aa:bb:cc:dd:ee:ff`
- `Time 12:34:56`
- `Ratio 1:2:3:4`
- `CSS color #ff00aa`
- `Version 1.2.3`
- `Port 80:443`
- `abc:def:ghi`
- `123:abc`
- `file:///path/to/file`
- `std::cout`
- `MyClass::toString`
- `:::`
- `IP192.168.1.1text`
- `text192.168.1.1`
- `256.256.256.256`
- `192.168.1.256`
- `gggg:hhhh::1234`
- `192.168.1`
- `300.168.1.1`
- `12345:db8::1`
- `2001::db8::1`
- `text::ffff:192.0.2.1`
- `foo2001:db8::10.0.0.1`
- `::ffff:256.0.0.1`
- `::ffff:192.168.1`
- `2001:db8::256.1.1.1`

### IBAN ✅
Source file: `presidio-analyzer/tests/test_iban_recognizer.py`

POSITIVE (~100 country-specific samples — both printed and machine forms):
`AL47212110090000000235698741`, `AL47 2121 1009 0000 0002 3569 8741`,
`AD1200012030200359100100`, `AD12 0001 2030 2003 5910 0100`,
`AT611904300234573201`, `AT61 1904 3002 3457 3201`,
`AZ21NABZ00000000137010001944`, `AZ21 NABZ 0000 0000 1370 1000 1944`,
`BH67BMAG00001299123456`, `BH67 BMAG 0000 1299 1234 56`,
`BY13NBRB3600900000002Z00AB00`, `BY13 NBRB 3600 9000 0000 2Z00 AB00`,
`BE68539007547034`, `BE71 0961 2345 6769`,
`BA391290079401028494`, `BA39 1290 0794 0102 8494`,
`BR9700360305000010009795493P1`, `BR97 0036 0305 0000 1000 9795 493P 1`,
`BG80BNBG96611020345678`, `BG80 BNBG 9661 1020 3456 78`,
`CR05015202001026284066`, `CR05 0152 0200 1026 2840 66`,
`HR1210010051863000160`, `HR12 1001 0051 8630 0016 0`,
`CY17002001280000001200527600`, `CY17 0020 0128 0000 0012 0052 7600`,
`CZ6508000000192000145399`, `CZ65 0800 0000 1920 0014 5399`,
`DK5000400440116243`, `DK50 0040 0440 1162 43`,
`DO28BAGR00000001212453611324`, `DO28 BAGR 0000 0001 2124 5361 1324`,
`TL380080012345678910157`, `TL38 0080 0123 4567 8910 157`,
`EE382200221020145685`, `EE38 2200 2210 2014 5685`,
`FO6264600001631634`, `FO62 6460 0001 6316 34`,
`FI2112345600000785`, `FI21 1234 5600 0007 85`,
`FR1420041010050500013M02606`, `FR14 2004 1010 0505 0001 3M02 606`,
`GE29NB0000000101904917`, `GE29 NB00 0000 0101 9049 17`,
`DE89370400440532013000`, `DE89 3704 0044 0532 0130 00`,
`GI75NWBK000000007099453`, `GI75 NWBK 0000 0000 7099 453`,
`GR1601101250000000012300695`, `GR16 0110 1250 0000 0001 2300 695`,
`GL8964710001000206`, `GL89 6471 0001 0002 06`,
`GT82TRAJ01020000001210029690`, `GT82 TRAJ 0102 0000 0012 1002 9690`,
`HU42117730161111101800000000`, `HU42 1177 3016 1111 1018 0000 0000`,
`IS140159260076545510730339`, `IS14 0159 2600 7654 5510 7303 39`,
`IE29AIBK93115212345678`, `IE29 AIBK 9311 5212 3456 78`,
`IL620108000000099999999`, `IL62 0108 0000 0009 9999 999`,
`IT60X0542811101000000123456`, `IT60 X054 2811 1010 0000 0123 456`,
`JO94CBJO0010000000000131000302`, `JO94 CBJO 0010 0000 0000 0131 0003 02`,
`KZ86125KZT5004100100`, `KZ86 125K ZT50 0410 0100`,
`XK051212012345678906`, `XK05 1212 0123 4567 8906`,
`KW81CBKU0000000000001234560101`, `KW81 CBKU 0000 0000 0000 1234 5601 01`,
`LV80BANK0000435195001`, `LV80 BANK 0000 4351 9500 1`,
`LB62099900000001001901229114`, `LB62 0999 0000 0001 0019 0122 9114`,
`LI21088100002324013AA`, `LI21 0881 0000 2324 013A A`,
`LT121000011101001000`, `LT12 1000 0111 0100 1000`,
`LU280019400644750000`, `LU28 0019 4006 4475 0000`,
`MT84MALT011000012345MTLCAST001S`, `MT84 MALT 0110 0001 2345 MTLC AST0 01S`,
`MR1300020001010000123456753`, `MR13 0002 0001 0100 0012 3456 753`,
`MU17BOMM0101101030300200000MUR`, `MU17 BOMM 0101 1010 3030 0200 000M UR`,
`MD24AG000225100013104168`, `MD24 AG00 0225 1000 1310 4168`,
`MC5811222000010123456789030`, `MC58 1122 2000 0101 2345 6789 030`,
`ME25505000012345678951`, `ME25 5050 0001 2345 6789 51`,
`NL91ABNA0417164300`, `NL91 ABNA 0417 1643 00`,
`MK07250120000058984`, `MK07 2501 2000 0058 984`,
`NO9386011117947`, `NO93 8601 1117 947`,
`PK36SCBL0000001123456702`, `PK36 SCBL 0000 0011 2345 6702`,
`PS92PALS000000000400123456702`, `PS92 PALS 0000 0000 0400 1234 5670 2`,
`PL61109010140000071219812874`, `PL61 1090 1014 0000 0712 1981 2874`,
`PT50000201231234567890154`, `PT50 0002 0123 1234 5678 9015 4`,
`QA58DOHB00001234567890ABCDEFG`, `QA58 DOHB 0000 1234 5678 90AB CDEF G`,
`RO49AAAA1B31007593840000`, `RO49 AAAA 1B31 0075 9384 0000`,
`SM86U0322509800000000270100`, `SM86 U032 2509 8000 0000 0270 100`,
`SA0380000000608010167519`, `SA03 8000 0000 6080 1016 7519`,
`RS35260005601001611379`, `RS35 2600 0560 1001 6113 79`,
`SK3112000000198742637541`, `SK31 1200 0000 1987 4263 7541`,
`SI56263300012039086`, `SI56 2633 0001 2039 086`,
`ES9121000418450200051332`, `ES91 2100 0418 4502 0005 1332`,
`SE4550000000058398257466`, `SE45 5000 0000 0583 9825 7466`,
`CH9300762011623852957`, `CH93 0076 2011 6238 5295 7`,
`TN5910006035183598478831`, `TN59 1000 6035 1835 9847 8831`,
`TR330006100519786457841326`, `TR33 0006 1005 1978 6457 8413 26`,
`AE070331234567890123456`, `AE07 0331 2345 6789 0123 456`,
`GB29NWBK60161331926819`, `GB29 NWBK 6016 1331 9268 19`,
`VA59001123000012345678`, `VA59 0011 2300 0012 3456 78`,
`VG96VPVG0000012345678901`, `VG96 VPVG 0000 0123 4567 8901`,
`this is an iban VG96 VPVG 0000 0123 4567 8901 in a sentence`,
`this is an iban VG96 VPVG 0000 0123 4567 8901 X in a sentence`,
`list of ibans: AL47212110090000000235698741, AL47212110090000000235698741`,
`Dash as iban separator: AL47-2121-1009-0000-0002-3569-8741`,
`AL47212110090000000235698741 ALL CAPS`.

NEGATIVE (~150 mutation-style rejection cases — sampled here):
`AL47 212A 1009 0000 0002 3569 8741`, `AL47 212A 1009 0000 0002 3569 874`,
`AL47 2121 1009 0000 0002 3569 8740`, `AD12000A2030200359100100`,
`AD12000A203020035910010`, `AD12 0001 2030 2003 5910 0101`,
`AT61 1904 A002 3457 3201`, `AT61 1904 3002 3457 320`,
`AT61 1904 3002 3457 3202`, `AZ21NABZ000000001370100019`,
`AZ21NABZ0000000013701000194`, `AZ21NABZ00000000137010001945`,
`BH67BMA100001299123456`, `BH67BMAG0000129912345`,
`BH67BMAG00001299123457`, `BY13NBRBA600900000002Z00AB00`,
`BY13 NBRB 3600 9000 0000 2Z00 AB0`, `BY13NBRB3600900000002Z00AB01`,
`BE71 A961 2345 6769`, `BE6853900754703`, `BE71 0961 2345 6760`,
`AB150120690000003111141`, `IL15 0120 6900 0000`,
`IL150120690000003111141`, `AM47212110090000000235698740`,
`Slash as iban separator: AL47/2121/1009/0000/0002/3569/8741`,
`Dalla's Pizza | 3843 Peartree Road, Bamblee, SD 20241 440-600-5124`,
`CY17 0020 0128 0000 0012 0052 7601 failed`,
(plus ~120 more single-char mutation rows — see upstream file).

### US passport ⚠️
Source file: `presidio-analyzer/tests/test_us_passport_recognizer.py`

POSITIVE:
- `912803456`
- `Z12803456`
- `A12803456`
- `my travel document is A12803456`
- `my travel passport is A12803456`

### US driver's license ✅
Source file: `presidio-analyzer/tests/test_us_driver_license_recognizer.py`

POSITIVE:
- `H12234567`

NEGATIVE:
- `C12T345672`
- `123456789 1234567890 12345679012 123456790123 1234567901234 1234`
- `ABCDEFG ABCDEFGH ABCDEFGHI`
- `ABCD ABCDEFGHIJ`

### US ITIN ✅
Source file: `presidio-analyzer/tests/test_us_itin_recognizer.py`

POSITIVE:
- `911-701234 91170-1234`
- `911701234`
- `911-70-1234`
- `911-53-1234`
- `911-64-1234`

NEGATIVE:
- `911-89-1234`
- `my tax id 911-89-1234`

### US bank account ✅
Source file: `presidio-analyzer/tests/test_us_bank_recognizer.py`

POSITIVE:
- `945456787654`

NEGATIVE:
- `1234567`

### US MBI (Medicare Beneficiary Identifier) ✅
Source file: `presidio-analyzer/tests/test_us_mbi_recognizer.py`

POSITIVE:
- `1EG4-TE5-MK73`
- `1EG4TE5MK73`
- `Patient 1EG4-TE5-MK73 and 2AG9-XC4-NN22`
- `9XX9-XX9-XX99`
- `Medicare ID: 3CD5-FG7-HJ89`
- `The MBI is 4EF6GH8JK12 for this patient`
- `1eg4-te5-mk73`

NEGATIVE:
- `1SG4-TE5-MK73`
- `1EG4-LE5-MK73`
- `1EG4-TE5-OK73`
- `1EG4-TE5-MI73`
- `1BG4-TE5-MK73`
- `1EG4-ZE5-MK73`
- `AEG4-TE5-MK73`
- `12G4-TE5-MK73`
- `1EG4TE5MK7`
- `1EG4TE5MK734`

### US NPI (National Provider Identifier) ⬜
Source file: `presidio-analyzer/tests/test_us_npi_recognizer.py`

POSITIVE:
- `1234567893`
- `1245319599`
- `1003000126`
- `1234-567-893`
- `1234 567 893`
- `NPI: 1234567893`
- `Provider identifier 1245319599`
- `NPI 1234567893 and NPI 1245319599`

NEGATIVE:
- `0234567893`
- `3234567893`
- `9234567893`
- `123456789`
- `12345678934`
- `1111111112`
- `1234567890`

### ABA routing ✅
Source file: `presidio-analyzer/tests/test_aba_routing_recognizer.py`

POSITIVE:
- `121000358`
- `3222-7162-7`
- `121042882`
- `0711-0130-7`

NEGATIVE:
- `421042111`
- `1234-0000-0`

### Crypto (Bitcoin) ✅
Source file: `presidio-analyzer/tests/test_crypto_recognizer.py`

POSITIVE:
- `16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ`
- `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`
- `bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq`
- `bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297`
- `16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`
- `my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ`

NEGATIVE:
- `16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2`
- `my wallet address is: 16Yeky6GMjeNkAiNcBY7ZhrLoMSgg1BoyZ2`
- `` (empty string)
- `8f953371d3e85eddb89b05ed6b9e680791055315c73e1025ab5dba7bb2aee189`

### Date / DOB ✅
Source file: `presidio-analyzer/tests/test_date_recognizer.py`

POSITIVE:
- `Today is 5-20-2021`
- `Today is 5/20/2021`
- `Today is 2021-05-21`
- `Today is 21.5.2021`
- `Today is 21.5.21`
- `Today is 5-MAY-2021`
- `Today is 5-May-2021`
- `Today is 05/21/21`
- `Today is 5/21/21`
- `Today is 21/05/21`
- `Today is 21/5/21`
- `Today is May-21`
- `Today is 21-May`
- `Today is 05-May`
- `Today is May-2021`
- `Today is 05/21`
- `Today is 5/21`
- `Today is 5/2021`
- `Today is 05/2021`
- `Today is 2024-06-05T09:15:30.500-07:00 or not?`
- `Today is,2024-03-15T14:30:00.123456Z or not?`
- `Today is\r2024-12-31T23:59:59+00:00 or not?`
- `Today is\n2024-03-15T14:30:00+02:00 or not?`
- `Today is 2024-03-15T14:30:00-05:00 or not?`
- `Today is 2024-03-15T14:30:00.123Z, or not?`
- `Today is 2024-03-15T14:30Z\r or not?`
- `Today is 2024-03-15T14:30Z\n or not?`
- `2024-03-15T14:30Z`
- `Today is,5/21,and it's sunny`
- `5-20-2021 is today.`
- `5-20-2021`

NEGATIVE:
- `Today is2024-06-05T09:15:30.500-07:00`
- `Today is5/21`
- `Today is5/21and it's sunny`

### UK NINO ✅
Source file: `presidio-analyzer/tests/test_uk_nino_recognizer.py`

POSITIVE:
- `AA 12 34 56 B`
- `hh 01 02 03 d`
- `tw987654a`
- `nino: PR 123612C`
- `Here is my National Insurance Number YZ 61 48 68 B`

NEGATIVE:
- `AA 12 34 56 H`
- `FQ 00 00 00 C`
- `BG123612A`
- `nino: nt 99 88 77 a`
- `This isn't a valid national insurance number UV 98 76 54 B`

### UK passport ✅
Source file: `presidio-analyzer/tests/test_uk_passport_recognizer.py`

POSITIVE:
- `AB1234567`
- `XY9876543`
- `ab1234567`
- `My passport number is CD7654321 and it expires soon`
- `Passports: AB1234567 and XY9876543`

NEGATIVE:
- `A12345678`
- `ABC123456`
- `AB123456`
- `AB12345678`
- `123456789`
- `AB 1234567`
- `1234567AB`
- `XYZAB1234567QRS`

### UK postcode ✅
Source file: `presidio-analyzer/tests/test_uk_postcode_recognizer.py`

POSITIVE:
- `M1 1AA`
- `M60 1NW`
- `W1A 1HQ`
- `CR2 6XH`
- `DN55 1PT`
- `EC1A 1BB`
- `GIR 0AA`
- `M11AA`
- `EC1A1BB`
- `DN551PT`
- `GIR0AA`
- `My address is SW1A 1AA in London`
- `Send to postcode EC2A 1NT please`
- `From SW1A 1AA to EC1A 1BB`

NEGATIVE:
- `QA1 1AA`
- `VA1 1AA`
- `XA1 1AA`
- `M1 1CA`
- `M1 1AI`
- `1A1 1AA`
- `ABCM11AADEF`

### UK driving licence ✅
Source file: `presidio-analyzer/tests/test_uk_driving_licence_recognizer.py`

POSITIVE:
- `MORGA607054SM9IJ`
- `MORGA657054SM9IJ`
- `FO999512018AA1AB`
- `SMIT9801015JK2CD`
- `Licence: MORGA607054SM9IJ ok`
- `morga607054sm9ij`
- `JONES710153J99EF`
- `SMITH802290AB1CD`
- `SMITH812310AB1CD`
- `SMITH851010AB1CD`
- `SMITH862310AB1CD`

NEGATIVE:
- `MORGA600054SM9IJ`
- `MORGA613054SM9IJ`
- `MORGA650054SM9IJ`
- `MORGA663054SM9IJ`
- `MORGA601004SM9IJ`
- `MORGA601324SM9IJ`
- `MORGA65705SM9IJ`
- `MORGA6570544SM9IJ`
- `99999657054SM9IJ`
- `MO9G9657054SM9IJ`

### UK NHS number ✅
Source file: `presidio-analyzer/tests/test_uk_nhs_recognizer.py`

POSITIVE:
- `401-023-2137`
- `221 395 1837`
- `0032698674`

NEGATIVE:
- `401-023-2138`

### CA SIN (Social Insurance Number) ✅
Source file: `presidio-analyzer/tests/test_ca_sin_recognizer.py`

POSITIVE:
- `130 692 544`
- `435 418 165`
- `948 584 792`
- `347-677-452`
- `731-530-150`
- `130692544`
- `550090112`
- `my SIN is 130-692-544`
- `mon NAS: 258 933 688`

NEGATIVE:
- `130 692 545`
- `130692545`
- `435-418-166`
- `046 454 286`
- `812 345 678`
- `111 111 111`
- `999 999 999`
- `046-454 286`
- `046 454-286`
- `13069254`
- `1306925440`

### AU TFN (Tax File Number) ✅
Source file: `presidio-analyzer/tests/test_au_tfn_recognizer.py`

POSITIVE:
- `876 543 210`
- `876543210`

NEGATIVE:
- `824 753 557`
- `824753557`
- `5282475355632`
- `52824753556AF`
- `51 824 753 5564`
- `123 456\n789`

### AU ABN (Australian Business Number) ⬜
Source file: `presidio-analyzer/tests/test_au_abn_recognizer.py`

POSITIVE:
- `51 824 753 556`
- `51824753556`

NEGATIVE:
- `52 824 753 556`
- `52824753556`
- `5282475355632`
- `52824753556AF`
- `51 824 753 5564`
- `123 456\n789`

### AU ACN (Australian Company Number) ⬜
Source file: `presidio-analyzer/tests/test_au_acn_recognizer.py`

POSITIVE:
- `000 000 019`
- `005 499 981`
- `006249976`

NEGATIVE:
- `824 753 557`
- `824753557`
- `5282475355632`
- `52824753556AF`
- `51 824 753 5564`
- `123 456\n789`

### AU Medicare ✅
Source file: `presidio-analyzer/tests/test_au_medicare_recognizer.py`

POSITIVE:
- `2123 45670 1`
- `2123456701`

NEGATIVE:
- `2123 25870 1`
- `2123258701`
- `212345670221`
- `2123456702AF`
- `123 456\n789`

### IN Aadhaar ✅
Source file: `presidio-analyzer/tests/test_in_aadhaar_recognizer.py`

POSITIVE:
- `312345678909`
- `399876543211`
- `3123 4567 8909`
- `3998 7654 3211`
- `3123-4567-8909`
- `3998-7654-3211`
- `3123:4567:8909`
- `3998:7654:3211`
- `My Aadhaar number is 400123456787 with a lot of text beyond it`

NEGATIVE:
- `123456789012`
- `1234 5678 9012`
- `1234-5678-9012`
- `1234:5678:9012`

### IN PAN ✅
Source file: `presidio-analyzer/tests/test_in_pan_recognizer.py`

POSITIVE:
- `AAASA1111R`
- `ABCPD1234Z`
- `ABCND1234Z`
- `A1111DFSFS`
- `My PAN number is ABBPM4567S with a lot of text beyond it`

NEGATIVE:
- `ABCD1234`

### IN passport ✅
Source file: `presidio-analyzer/tests/test_in_passport_recognizer.py`

POSITIVE:
- `A3456781`
- `B3097651`
- `C3590543`
- `my passport number is T3569075`
- `passport number: J6932157`

NEGATIVE:
- `b0097650`
- `my passport number is T356907`

### IN voter ID ⬜
Source file: `presidio-analyzer/tests/test_in_voter_recognizer.py`

POSITIVE:
- `KSD1287349`
- `my voter: DBJ2289013`
- `uzb2345117`
- `this MUP5632811`
- `You can vote with your CPJ4467918 number`

NEGATIVE:
- `zxdf8923q1`
- `A8923571WZ`

### IN GSTIN ⬜
Source file: `presidio-analyzer/tests/test_in_gstin_recognizer.py`

POSITIVE:
- `27ABCDE1234F1Z5`
- `07PQRST6789K1Z2`
- `01ABCDE1234F1Z5`
- `37ABCDE1234F1Z5`
- `My GSTIN number is 27ABCDE1234F1Z5 for business registration`
- `GST registration: 07PQRST6789K1Z2`
- `Tax identification GSTIN: 01ABCDE1234F1Z5`
- `GSTINs: 27ABCDE1234F1Z5 and 07PQRST6789K1Z2`
- `ABCDE1234F`
- `PQRST6789K`
- `27-ABCDE-1234-F1-Z5`
- `27 ABCDE 1234 F1 Z5`
- `The company GSTIN is 27ABCDE1234F1Z5 for tax purposes`

NEGATIVE:
- `27ABCDE1234F1Z`
- `27ABCDE1234F1Z55`
- `00ABCDE1234F1Z5`
- `38ABCDE1234F1Z5`
- `27ABCDE1234F1Y5`
- `` (empty)
- `123456789012345`
- `ABCDEFGHIJKLMNO`
- `ABCD1234F`
- `ABCDE12345F`
- `12345ABCDE`
- `ABCDE1234`

### IN vehicle registration ⬜
Source file: `presidio-analyzer/tests/test_in_vehicle_registration_recognizer.py`

POSITIVE:
- `KA53ME3456`
- `KA99ME3456`
- `MN2412`
- `MCX1243`
- `I15432`
- `DL3CJI0001`
- `My Bike's registration number is OD02BA2341 with a lot of text beyond`

NEGATIVE:
- `ABNE123456`

### ES NIF ✅
Source file: `presidio-analyzer/tests/test_es_nif_recognizer.py`

POSITIVE:
- `55555555K`
- `55555555-K`
- `1111111-G`
- `1111111G`
- `01111111G`

NEGATIVE:
- `401-023-2138`

### ES NIE ⬜
Source file: `presidio-analyzer/tests/test_es_nie_recognizer.py`

POSITIVE:
- `Z8078221M`
- `X9613851N`
- `Y8063915Z`
- `Y8063915-Z`
- `Mi NIE es X9613851N`
- `Z8078221M en mi NIE`
- `Mi Número de identificación de extranjero es Y8063915-Z`

NEGATIVE:
- `Y8063915Q`
- `Y806391Q`
- `58063915Q`
- `W8063915Q`

### ES passport ✅
Source file: `presidio-analyzer/tests/test_es_passport_recognizer.py`

POSITIVE:
- `AAA123456`
- `XYZ987654`
- `Mi pasaporte es AAA123456`
- `AAA123456 es mi número de pasaporte`
- `aaa123456`
- `xyz987654`
- `Mi pasaporte es aaa123456`
- `aaa123456 es mi número de pasaporte`
- `AaA123456`
- `XyZ987654`
- `Mi pasaporte es AaA123456`
- `AaA123456 es mi número de pasaporte`

NEGATIVE:
- `AA123456`
- `AAAA12345`
- `AAA12345`

### DE passport ✅
Source file: `presidio-analyzer/tests/test_de_passport_recognizer.py`

POSITIVE:
- `C01234565`
- `F12345671`
- `L01X00T44`
- `CZ6311T03`
- `G00000002`
- `C01X00T41`
- `Reisepass C01234565 ausgestellt am 01.01.2020.`
- `Pass-Nr.: F12345671`
- `c01234565`

NEGATIVE:
- `C01234567`
- `F12345678`
- `L01X00T47`
- `C0123456`
- `C012345678`
- `901234567`
- `C0123456A`
- `A01234567`
- `IOQSUBDE1`

### DE ID card ⬜
Source file: `presidio-analyzer/tests/test_de_id_card_recognizer.py`

POSITIVE (nPA format):
- `L01X00T44`
- `C01234565`
- `CZ6311T03`
- `G00000002`
- `l01x00t44`
- `Personalausweis: L01X00T44.`

POSITIVE (Legacy T-Format):
- `T22000129`
- `T00000000`
- `T99999999`
- `t22000129`
- `Ausweis Nr. T22000129 gültig bis 2025.`

NEGATIVE:
- `L01X00T47`
- `C01234567`
- `T2200012`
- `T220001290`
- `L01X00T4`
- `L01X00T440`
- `123456789`
- `L01X00T4A`

### DE tax ID ⬜
Source file: `presidio-analyzer/tests/test_de_tax_id_recognizer.py`

POSITIVE:
- `12345678903`
- `98765432106`
- `Meine Steuer-ID: 12345678903.`
- `IdNr. 98765432106 liegt vor.`

NEGATIVE:
- `12345678901`
- `98765432100`
- `02345678901`
- `1234567890`
- `123456789030`
- `11111111111`
- `11112345678`
- `abcdefghijk`
- `02345678903`
- `12222234567`

### IT fiscal code ⬜
Source file: `presidio-analyzer/tests/test_it_fiscal_code_recognizer.py`

POSITIVE:
- `AAAAAA00B11C333Y`
- `AAAAAA00B11C333N`
- `AAAAAA00B11C333Y and AAAAAA00B11C333N`

NEGATIVE:
- `AAAAAA - 00B11C333N`
- `A55AAA00B11C333N`

### IT driver's license ⬜
Source file: `presidio-analyzer/tests/test_it_driver_license_recognizer.py`

POSITIVE:
- `AA0123456B`
- `AA0123456B and AA0123456B`
- `U1H00B000C`
- `U1K711J11M`
- `license U1K711J11M here`

NEGATIVE:
- `U1H00A000B`
- `990123456B`

### PL PESEL ✅
Source file: `presidio-analyzer/tests/test_pl_pesel_recognizer.py`

POSITIVE:
- `44051401458`
- `My pesel is 44051401458.`
- `02070803628`
- `11111111116`

NEGATIVE:
- `44051401459`
- `85040812345`
- `1111321111`
- `11110021111`
- `11-11-11-11114`
- `4405140145`
- `440514014588`
- `4405140145A`
- `44-051401458`

### SE personnummer ⬜
Source file: `presidio-analyzer/tests/test_se_personnummer_recognizer.py`

POSITIVE:
- `189004119807`
- `My personal identity code is: 189110089811. Thank you.`
- `191005059801`
- `198712202384`
- `871220-2384`
- `199109242397 är mitt pnr.`
- `19910924-2397 är mitt pnr.`
- `199201232387`
- `9201232387`
- `Here's my personnummer 200109022392.`
- `201109252385`
- `20110925-2385`
- `My swedish id code is199003052397.`

NEGATIVE:
- `19000309-3393`
- `19001309-2393`
- `200504422381`
- `189x09179809`
- `18970c17-9809`

### SE organisationsnummer ⬜
Source file: `presidio-analyzer/tests/test_se_organisationsnummer_recognizer.py`

POSITIVE:
- `212000-0142`
- `Our company identity code is: 212000-0142. Thank you.`
- `2120000142`
- `556703-7485`
- `5567037485`
- `556703-7485 är vårt orgnummer.`
- `556703-7485 tillhör vårt företag.`

NEGATIVE:
- `19000309-3393`
- `19001309-2393`
- `55670x-7485`
- `556703-7r85`

### SG FIN / NRIC ✅
Source file: `presidio-analyzer/tests/test_sg_fin_recognizer.py`

POSITIVE:
- `S2740116C`
- `T1234567Z`
- `F2346401L`
- `G1122144L`
- `M4332674T`
- `S9108268C T7572225C`
- `NRIC S2740116C was processed`

NEGATIVE:
- `A1234567Z`
- `B1234567Z`
- `PA12348L`
- `` (empty)

### SG UEN ⬜
Source file: `presidio-analyzer/tests/test_sg_uen_recognizer.py`

POSITIVE:
- `53125226D`
- `201434292D`
- `T16RF0037C`
- `S57TU0392K`
- `53125226D 201434292D S57TU0392K`
- `UEN 53125226D was processed`

NEGATIVE:
- `53125226`
- `` (empty)

### TH TNIN (Thai National ID) ⬜
Source file: `presidio-analyzer/tests/test_th_tnin_recognizer.py`

POSITIVE:
- `1234567890121`
- `2345678901234`
- `3456789012347`
- `4567890123459`
- `5678901234560`
- `My Thai ID is 1234567890121`
- `TNIN: 2345678901234`
- `เลขประจำตัวประชาชน: 3456789012347`
- `Thai National ID 1234567890121`
- `เลขบัตรประชาชน 2345678901234`

NEGATIVE:
- `123456789012`
- `12345678901234`
- `123456789012a`
- `123456789012 `
- `0234567890124`
- `1034567890124`
- `1234567890123`
- `2345678901235`
- `3456789012346`
- `0000000000000`
- `1111111111111`

### TR (Turkish) national ID / TCKN ⬜
Source file: `presidio-analyzer/tests/test_tr_national_id_recognizer.py`

POSITIVE:
- `10000000146`
- `76543210794`
- `36493665440`
- `53857632436`
- `94357219628`
- `79059236630`
- `64625294480`
- `TC Kimlik No: 10000000146`
- `Başvuru sahibinin TCKN numarası 10000000146 olarak tescil edilmiştir.`
- `Birinci kişi: 10000000146, ikinci kişi: 76543210794`
- `Turkish ID 10000000146`
- `Türk kimlik numarası 36493665440`

NEGATIVE:
- `00000000000`
- `02531814694`
- `12345678900`
- `76543210780`
- `83219500748`
- `11798724308`
- `10000000145`
- `62286775983`
- `97485249605`
- `1234567890`
- `123456789012`
- `abcdefghijk`

### TR phone number ⬜
Source file: `presidio-analyzer/tests/test_tr_phone_number_recognizer.py`

POSITIVE:
- `+905321234567`
- `+90 532 123 45 67`
- `+90-532-123-45-67`
- `+90 (532) 123 45 67`
- `05321234567`
- `0 532 123 45 67`
- `0-532-123-45-67`
- `0 (532) 1234567`
- `5321234567`
- `532 123 45 67`
- `532-123-45-67`
- `Telefon numaram +905321234567 olarak kayitli.`
- `Cep no: 05321234567`
- `Phone: 5321234567`
- `Birinci: +905321234567, Ikinci: 05359876543`
- `4321234567`
- `2121234567`
- `3121234567`
- `4621234567`
- `02121234567`
- `0216 123 45 67`
- `0232 123 45 67`
- `0312 123 45 67`
- `0412 123 45 67`
- `532.123.45.67`

NEGATIVE:
- `532123456`
- `53212345678`
- `hello world`
- `1234567890`
- `12345678901`
- `15053212345678`
- `10000000146`
- `34 ABC 1234`
- `1123456789`
- `6123456789`
- `7123456789`
- `8123456789`
- `9123456789`

### TR license plate ⬜
Source file: `presidio-analyzer/tests/test_tr_license_plate_recognizer.py`

POSITIVE:
- `34 ABC 1234`
- `06 A 123`
- `35 JK 12`
- `16 B 1234`
- `34ABC1234`
- `34 abc 1234`
- `Araç plakası 34 ABC 1234 olarak kayıtlıdır.`
- `Plaka 34 ABC 1234 ve 06 JK 567`
- `01 A 12`
- `81 A 12`
- `07 AB 123`
- `License plate 34 ABC 1234`
- `Plaka numarası 06 A 123 olarak kayıtlı`

NEGATIVE:
- `00 ABC 123`
- `82 ABC 123`
- `99 ABC 123`
- `hello world`
- `1234567890`
- `12`
- `` (empty)
- `AB ABC 123`
- `XY 123`

### FI personal identity code ⬜
Source file: `presidio-analyzer/tests/test_fi_personal_identity_code_recognizer.py`

POSITIVE:
- `010594Y9032`
- `My personal identity code is: 010594Y9032. Thank you.`
- `010594Y9021`
- `020594X903P`
- `020594X903P is my hetu.`
- `020594X902N`
- `Here's my henkilötunnus 020594X902N.`
- `030594W903B`
- `My finnish id code is030594W903B.`
- `030694W9024`
- `040594V9030`
- `040594V902Y`
- `050594U903M`
- `050594U902L`
- `010516B903X`
- `010516B902W`
- `020516C903K`
- `020516C902J`
- `030516D9037`
- `030516D9026`
- `010501E9032`
- `020502E902X`
- `020503F9037`
- `020504A902E`
- `020504B904H`

NEGATIVE:
- `111111-111A`
- `111111+110G`
- `311190-1111`
- `310289-211C`
- `012245A110G`
- `010324A110G`

### PH (Philippines) mobile number ⬜
Source file: `presidio-analyzer/tests/test_ph_mobile_number_recognizer.py`

POSITIVE:
- `+63 917 123 4567`
- `+639171234567`
- `+63-917-123-4567`
- `+63 (917) 123 4567`
- `09171234567`
- `0917 123 4567`
- `0917-123-4567`
- `0 (917) 123 4567`
- `09181234567`, `09191234567`, `09201234567`, `09211234567`,
  `09271234567`, `09281234567`, `09291234567`, `09301234567`,
  `09391234567`, `09471234567`, `09491234567`, `09561234567`,
  `09611234567`, `09661234567`, `09671234567`, `09771234567`,
  `09941234567`, `09951234567`, `09961234567`, `09971234567`,
  `09981234567`, `09991234567`
- `My mobile number is +639171234567.`
- `Telepono: 09171234567`
- `First: +639171234567, Second: 09181234567`

NEGATIVE:
- `9171234567`
- `917 123 4567`
- `917-123-4567`
- `Numero: 9171234567`
- `12345678901`
- `0917123456`
- `091712345678`
- `15091712345678`
- `hello world`

---

## Source: scrubadub (Apache 2.0, unmaintained since 2022)

Repo: <https://github.com/LeapBeyond/scrubadub>
Detector tests live under `tests/`.

### Email ✅
Source file: `tests/test_detector_emails.py`

POSITIVE:
- `My email is john@gmail.com`
- `My email is John@gmail.com`
- `My email is John1@example.com`
- `My email is adam80@example.info`
- `My email is HELLO@EXAMPLE.COM`

NEGATIVE / fuzzy MISS:
- `My email is john at gmail.com`

### Phone numbers ✅
Source file: `tests/test_detector_phone_numbers.py`

POSITIVE:
- `1-312-515-2239`
- `+1-312-515-2239`
- `1 (312) 515-2239`
- `312-515-2239`
- `(312) 515-2239`
- `(312)515-2239`
- `312-515-2239 x12`
- `312-515-2239 ext. 12`
- `312-515-2239 ext.12`
- `+47 21 30 85 99`
- `+45 69 19 88 56`
- `+46 852 503 499`
- `+31 619 837 236`
- `+86 135 3727 4136`
- `+61267881324`
- `Call me on my cell 312.714.8142 or in my office 773.415.7432`

### URLs ✅
Source file: `tests/test_detector_urls.py`

POSITIVE:
- `http://bit.ly/aser is neat`
- `https://bit.ly/aser is neat`
- `www.bit.ly/aser is neat`
- `https://this.is/a/long?url=very#url is good`
- `http://bit.ly/number-one http://www.google.com/two`
- `Find jobs at http://facebook.com/jobs`
- `http://public.com/this/is/very/private`
- `http://public.com/`

### Credit card ✅
Source file: `tests/test_detector_credit_card.py`

POSITIVE:
- `My credit card is 378282246310005.`
- `My credit card is 371449635398431.`
- `My credit card is 378734493671000.`
- `My credit card is 30569309025904.`
- `My credit card is 38520000023237.`
- `My credit card is 6011111111111117.`
- `My credit card is 6011000990139424.`
- `My credit card is 3530111333300000.`
- `My credit card is 3566002020360505.`
- `My credit card is 5555555555554444.`
- `My credit card is 5105105105105100.`
- `My credit card is 4111111111111111.`
- `My credit card is 4012888888881881.`

### US SSN ✅
Source file: `tests/test_detector_en_US_social_security_number.py`

POSITIVE:
- `My social security number is 726-60-2033`
- `My social security number is 109-99-6000`
- `My social security number is 109.99.6000`
- `My social security number is 109 99 6000`

### Postal codes ✅
Source file: `tests/test_detector_postal_codes.py`

POSITIVE:
- `BX1 1LT`
- `sw1A 0AA`
- `EC2V 7hh`
- `M25DB`
- `eh12ng`
- `BT1 5GS`
- `EC1A 1BB`
- `W1A 0AX`
- `M1 1AE`
- `B33 8TH`
- `CR2 6XH`
- `DN55 1PT`
- `CM2 0PP`
- `EC3M 5AD`

NEGATIVE:
- `1`
- `23`
- `456`
- `4567`
- `750621`
- `95130-642`
- `95130-64212`

### UK National Insurance Number ✅
Source file: `tests/test_detector_en_GB_nino.py`

POSITIVE (positive in scrubadub, mostly MISS for us due to spaces):
- `My NI number is AZ 12 34 56 A`
- `Enter a National Insurance number that is 2 letters, 6 numbers, then A, B, C or D, like AZ123456A.`
- `It's on your National Insurance card, benefit letter, payslip or P60. For example, AZ 12 34 56 A.`
- `Please verify the NI AZ 123456 A.`
- `The number is AZ 123 456 A.`

### UK Tax Reference Number (TRN / UTR) ⬜
Source file: `tests/test_detector_en_GB_trn.py`

POSITIVE:
- `99L99999`
- `11 A 12345`
- `99L 99999`
- `99 L 999 99`
- `11A 12345`

### UK driving licence ⬜
Source file: `tests/test_detector_drivers_licence.py`

POSITIVE:
- `The driving licence number of the claimant is MORGA753116SM91J 01, and a copy of the licence is attached.`
- `My DVLA NO is MORGA 753116SM91J 01 could you please check.`
- `My DVLA NO is MORGA753116SM91J01 could you please check.`
- `My DVLA NO is MORGA 753 116 SM91J 01 could you please check.`
- `My DVLA NO is MORGA 753116 SM91J01 could you please check.`

### Date of birth ✅
Source file: `tests/test_detector_date_of_birth.py`

POSITIVE:
- `My date of birth is 17/06/1976.`
- `I was born 15th June 1991`
- `DOB: 02.12.1979`
- `My name is Mike and I was born in a land far away on 22/11/1972`
- `my name is Jane and I was born on 11/22/1972`
- `my date of birth is 22-nov-1972`
- `My dob is 22-11-1972`
- `The claimant's, d.o.b. is 4 June 1976`
- `1985-01-01 is my birthday.`
- `the big day is may 14th 1983\nsee you then`

NEGATIVE:
- `my birthday is not may 14th 2020\nor may 15th 2020\nor +14-05-2020 23`

### Twitter handle ✅
Source file: `tests/test_detector_twitter.py`

POSITIVE:
- `My email is john@gmail.com and i tweet at @john_gmail`
- `My tweeter is @John_gmail`
- `My tweeter is @JOHN_JOHN123`
- `My tweeter is @_JOHN_JOHN123`
- `My tweeter is @_JOHN_JOHN123_`

NEGATIVE (scrubadub treats as invalid via known-handles list; we fire):
- `This is an invalid handle @TwitterInfo`
- `This is an invalid handle @XYZAdminInfo`

### Skype handle ✅
Source file: `tests/test_detector_skype.py`

POSITIVE:
- `contact me on skype (dean.malmgren) to chat`
- `i'm dean.malmgren on skype`
- `i'm on skype (dean.malmgren) or can be reached on my cell`
- `skype: dean.malmgren\nnerd`
- `I have added you on Skype. My ID is dean.malmgren`
- `joecool`, `joe,cool`, `joe.cool`, `joe-cool` (template fills `My Skype is %s`)
- `SCREAM to get my attention on Skype (dean.malmgren)`

NEGATIVE:
- `SCREAM to get my attention because Im not on instant messengers`

### Credentials (username/password pairs) ✅ (unsupported in our layer)
Source file: `tests/test_detector_credentials.py`

POSITIVE:
- `username: root\npassword: root\n\n`
- `username:root\npassword:crickets`
- `username root\npassword crickets`
- `username: joe@example.com\npassword moi`
- `login snoop pw biggreenhat`
- `u: snoop\np: biggreenhat`
- `UserName snoop PassWord biggreenhat`

NEGATIVE:
- `This is your problem`

### Address (UK shapes) ✅
Source file: `tests/test_filth_address.py`

POSITIVE:
- `4 Paula views\nLake Howardburgh\nN7U 2FQ`
- `79 Miller branch\nJordantown\nW1F 3LB`
- `78 Joseph keys\nEast Patricktown\nEN6 2SD`
- `93 Hall overpass\nNashbury\nTA2W 9XP`
- `Flat 98R\nNatasha fall\nLake Rosie\nB73 8PJ`
- `8 Roberts stravenue\nElliottville\nSY18 2YP`
- `784 Knowles mall\nJunetown\nIM20 2PG`

### Names (NER via TextBlob) ✅ (unsupported in our layer)
Source file: `tests/test_detector_text_blob.py`

POSITIVE:
- `John is a cat`
- `sarah is a friendly person`

NEGATIVE:
- `Hello. Please testing.`

### Locations (NER) ✅ (unsupported)
Source file: `tests/test_filth_location.py`

POSITIVE:
- `Brianland`

### Organizations (NER) ✅ (unsupported)
Source file: `tests/test_filth_organization.py`

POSITIVE:
- `Brown-Lindsey`

---

## Source: CommonRegex (MIT, unmaintained since 2021)

Repo: <https://github.com/madisonmay/CommonRegex>
Test file: `test.py`

### Dates ⬜

Numeric:
- `1-19-14`, `1.19.14`, `01.19.14`

Verbose:
- `January 19th, 2014`, `Jan. 19th, 2014`, `Jan 19 2014`, `19 Jan 2014`

### Times ⬜
- `09:45`, `9:45`, `23:45`, `9:00am`, `9am`, `9:00 A.M.`, `9:00 pm`

### Phone ✅
- `12345678900`, `1234567890`, `+1 234 567 8900`, `234-567-8900`,
  `1-234-567-8900`, `1.234.567.8900`, `5678900`, `567-8900`,
  `(123) 456 7890`, `+41 22 730 5989`, `(+41) 22 730 5989`,
  `+442345678900`

### Phone with extension ✅
- `(523)222-8888 ext 527`, `(523)222-8888x623`, `(523)222-8888 x623`,
  `(523)222-8888 x 623`, `(523)222-8888EXT623`, `523-222-8888EXT623`,
  `(523) 222-8888 x 623`

### Links ✅
- `www.google.com`, `http://www.google.com`, `sub.example.com`,
  `http://www.google.com/%&#/?q=dog`, `google.com`

### Emails ✅
- `john.smith@gmail.com`, `john_smith@gmail.com`, `john@example.net`

### IPs (IPv4) ✅
- `127.0.0.1`, `192.168.1.1`, `8.8.8.8`

### IPv6 ⬜
- `fe80:0000:0000:0000:0204:61ff:fe9d:f156`
- `fe80:0:0:0:204:61ff:fe9d:f156`
- `fe80::204:61ff:fe9d:f156`
- `fe80:0000:0000:0000:0204:61ff:254.157.241.86`
- `fe80:0:0:0:0204:61ff:254.157.241.86`
- `fe80::204:61ff:254.157.241.86`
- `::1`

### Prices ⬜
- `$1.23`, `$1`, `$1,000`, `$10,000.00`

### Hex colors ⬜
- `#fff`, `#123`, `#4e32ff`, `#12345678`

### Credit cards ✅
- `0000-0000-0000-0000`, `0123456789012345`, `0000 0000 0000 0000`,
  `012345678901234`

### BTC addresses ⬜
- `1LgqButDNV2rVHe9DATt6WqD8tKZEKvaK2`
- `19P6EYhu6kZzRy9Au4wRRZVE8RemrxPbZP`
- `1bones8KbQge9euDn523z5wVhwkTP3uc1`
- `1Bow5EMqtDGV5n5xZVgdpRPJiiDK6XSjiC`

### Street addresses ✅
- `checkout the new place at 101 main st.`
- `504 parkwood drive`
- `3 elm boulevard`
- `500 elm street ` (trailing space preserved)

### PO Boxes ✅
- `PO Box 123456`
- `hey p.o. box 234234 hey`

### ZIP codes ⬜
- `02540`, `02540-4119`

### SSNs ✅
- `523 23 4566` (space form — known MISS for us)
- `523-04-1234`

---

## Coverage summary

* **Fully wired into our test suite** (✅): email, credit card, SSN,
  phone, URL, IPv4, IPv6 (partial), IBAN, US passport, US driver's
  license, US ITIN, US bank, US MBI, US zip, ABA routing, crypto,
  date / DOB, UK NINO, UK passport, UK postcode, UK driving licence,
  UK NHS, CA SIN, AU TFN, AU Medicare, IN Aadhaar, IN PAN, IN passport,
  ES NIF, ES passport, DE passport, PL PESEL, SG FIN, scrubadub email
  / phone / URL / CC / SSN / postcodes / NINO / DOB / Twitter / Skype
  / credentials / address / names / locations / orgs, CommonRegex
  phone / phone-ext / links / emails / IPv4 / credit cards / street
  addresses / PO boxes / SSNs.
* **TDD lock wired in `_UNSUPPORTED_TYPE_CORPORA`** (✅): the
  remaining types are locked in
  `agent_core_lib/tests/test_pii_third_party_corpora.py`'s
  `_UNSUPPORTED_TYPE_CORPORA` dict — one key per type, every upstream
  POSITIVE input as the value. The
  `test_unsupported_type_locks_no_dedicated_pattern_fires` method
  walks every entry and asserts the named pattern does NOT fire
  (trivially true today; load-bearing the moment a detector is
  added). The companion
  `test_unsupported_types_cover_documented_gap_set` locks the key
  set itself so adding a new detector forces a corresponding lock
  removal. The wired types are:
    * US NPI
    * AU ABN, AU ACN
    * IN voter ID, IN GSTIN, IN vehicle registration
    * ES NIE
    * DE ID card, DE tax ID
    * IT fiscal code, IT driver's license
    * SE personnummer, SE organisationsnummer
    * SG UEN
    * TH TNIN
    * TR national ID, TR phone, TR license plate
    * FI personal identity code
    * PH mobile number
    * UK driving licence (scrubadub corpus), UK TRN
    * Time of day, Price, Hex color, BTC legacy explicit list,
      IPv6 with embedded IPv4, Calendar date (CommonRegex)

Every adversarial input from every upstream library's test file that
we've fetched is now exercised by our suite — either as a positive
match assertion, a negative match assertion, a documented over-match
lock, a documented MISS lock, or a TDD unsupported-type lock.

---

## What to do with this file

* **Hardening cycle** — when adding a new pattern to
  `pii_patterns.py`, find the matching section here and copy the
  POSITIVE inputs into the test corpus for the new pattern. Every
  string here has already been adversarially curated by an upstream
  library's maintainers.
* **Re-fetch** — the upstream files evolve; the URLs in each section
  header let the next maintainer diff against newer versions. A
  ``git log`` on this file should show one section update per upstream
  re-pull.
* **Don't depend on the libraries at runtime** — Presidio is heavy
  (spaCy install ~500MB–1.5GB), scrubadub is parked since 2022,
  CommonRegex is parked since 2021. We borrow the *test data*, not
  the *code*. See `pii_patterns.py`'s "Prior-art note" block for the
  full why-we-don't-import survey.

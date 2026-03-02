# **SmartSecLab CVE and patch links**

Programvare-sårbarheter utgjør en betydelig risiko for brukere, både for organisasjoner og for
privatpersoner. Når en sårbarhet oppdages blir den ofte publisert som en CVE, common
vulnerabilities and exposures, hvor sårbarheten beskrives, hva som er feil, hvilke systemer
som er rammet og sårbarhetens alvorlighetsgrad.

Det som derimot ofte mangler er en tydelig kobling til hvordan sårbarheten blir rettet i kode. I
praksis skjer retting av sårbarheter gjennom kodeendringer kalt patches i
versjonskontrollsystemer som Git. Disse patchesene finnes i commits i åpne kildekode
repositories, som på GitHub. Å manuelt identifisere hvilke commits som representerer
sikkerhets patches og å koble dem til riktig CVE er tidskrevende og lite effektivt.

Dette prosjektet skal adressere dette problemet ved å designe og utvikle et automatisert
rammeverk i python som samler inn, identifiserer og strukturerer sikkerhets patches fra
kildekode repositories i Git og å koble dem opp til kjente sårbarheter oppført i CVE
databasen. Rammeverket skal støtte flere programmeringsspråk. Prosjektet etterspør
hovedsakelig spesialkompetanse innen fundamental cyber sikkerhets-kunnskap, gode python
programmeringsevner, kunnskap innen git- og versjonskontrollsystemer og generell database
og SQL kunnskaper. Produktet skal bidra til at bedriften oppnår bedre oversikt og kontroll
over sitt sikkerhetsarbeid ved å styrke innsatsen innen analyse og sikkerhetsstyring.

Løsningen representerer en videre utvikling av et allerede påbegynt prosjekt, som på sikt skal
ferdigstilles og forhåpentligvis tas i full operativ bruk. På denne måten kan bedriften bygge
videre på eksisterende arbeid og samtidig videreutvikle løsninger over tid. Dette sikrer
kontinuitet i utviklingsarbeidet og legger et solid grunnlag for fremtidige forbedringer og
tilpasninger. En av produktets viktigste egenskaper er den automatiske koblingen mellom
registrerte sårbarheter (CVE-er) og relevante, oppdaterte patcher.

Ved å redusere behovet for manuell kartlegging av relevante sikkerhetsoppdateringer, bidrar
løsningen til å redusere tidsbruken knyttet til sårbarhetsoppdatering sammenlignet med
dagens manuelle prosesser. Når bedriften slipper å identifisere å lete etter riktige patcher på
egen hånd, blir håndteringen både raskere og mer presis, samtidig som risikoen for å overse
kritiske oppdateringer reduseres.

Automatiseringen av prosessen reduserer den administrative belastningen på bedriften og
frigjør ressurser som i stedet kan benyttes til mer verdiskapende sikkerhetsarbeid. Mindre
manuelt arbeid bidrar til økt effektivitet, bedre arbeidsflyt og mer konsistent håndtering av
sikkerhetsrelaterte oppgaver. Samlet sett legger produktet til rette for en mer strukturert,
effektiv og proaktiv tilnærming til sårbarhetshåndtering i virksomheten.

# **Installasjon**



Åpne terminalen, og klon prosjektet:
```bash
git clone https://github.com/Sunniiiva/BAO304.git
``` 


# **bruk av verktøy**
Verktøyet brukes ved command line interface. Bruk python -m  src.main --help for å informasjon om bruk av verktøyet.


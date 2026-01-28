from cve import fetch_cve
from repo import fetch_commit
from patch import fetch_patch


# kalle moduler i rekkefølge: fetch_cve, fetch_commit, fetch_patch, 

fetch_cve.load_cve_from_file(file)


# logging og feilhåntering

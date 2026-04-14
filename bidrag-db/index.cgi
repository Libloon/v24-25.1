#!/bin/sh

# start: Konfigurerbar databasebane og intern admin-url for herdet Kubernetes-drift - oppfyller F3 (persistens), NF1 (minste privilegium) og NF3 (stabil lokal kjøring) (person 4)
DB="${BIDRAG_DB_PATH:-../bidrag.db}"
PSEUDONYM_INTERNAL_URL="${PSEUDONYM_INTERNAL_URL:-http://127.0.0.1:8083/cgi-bin/index.cgi}"

# start: SQLCipher-nøkkel fra Kubernetes Secret i steg 9 - oppfyller F3 (persistens), NF1 (ingen hardkodede hemmeligheter) og NF7 (kryptering av data at rest og nokkelhandtering) (person 4 og person 5)
KEY_FILE="${BIDRAG_DB_KEY_FILE:-/run/secrets/storage/bidrag-db-key}"

les_hemmelighet() {
    FIL="$1"

    if [ ! -s "$FIL" ]; then
        echo "Manglende databasenokkel." >&2
        exit 1
    fi

    tr -d '\r\n' < "$FIL"
}

sqlcipher_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

SQLCIPHER_KEY=$(les_hemmelighet "$KEY_FILE")
SQLCIPHER_KEY_SQL=$(sqlcipher_escape "$SQLCIPHER_KEY")

db_query() {
    sqlcipher "$DB" <<EOF
PRAGMA key = '$SQLCIPHER_KEY_SQL';
$1
EOF
}

# start: Renser enkelverdier fra SQLCipher-oppslag i steg 9 - oppfyller F1 (stabil autentisering) og NF1 (integritet i autentiseringsflyt) (person 4 og person 5)
db_scalar() {
    db_query "$1" 2>/dev/null | awk 'NF && $0 != "ok" { print; exit }' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}
# slutt: Renser enkelverdier fra SQLCipher-oppslag i steg 9 - oppfyller F1 (stabil autentisering) og NF1 (integritet i autentiseringsflyt) (person 4 og person 5)

db_query_line() {
    RESULT=$(sqlcipher -line "$DB" 2>/dev/null <<EOF
PRAGMA key = '$SQLCIPHER_KEY_SQL';
$1
EOF
)
    printf '%s\n' "$RESULT" | grep -v '^ok = ok$'
}
# slutt: SQLCipher-nokkel fra Kubernetes Secret i steg 9 - oppfyller F3 (persistens), NF1 (ingen hardkodede hemmeligheter) og NF7 (kryptering av data at rest og nøkkelhandtering) (person 4 og person 5)
# slutt: Konfigurerbar databasebane og intern admin-url for herdet Kubernetes-drift - oppfyller F3 (persistens), NF1 (minste privilegium) og NF3 (stabil lokal kjøring) (person 4)

# start: Person 2  innhold + visninger (F1, F2, NF1)
url_param() {
    KEY="$1"
    echo "$QUERY_STRING" | tr '&' '\n' | awk -F= -v k="$KEY" '$1==k { print substr($0, index($0, "=")+1); exit }'
}

trim() {
    printf '%s' "$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

sql_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

xml_felt() {
    FELT="$1"
    printf '%s' "$KR" | xmllint --xpath "string(/bidrag/$FELT)" - 2>/dev/null
}

xml_escape() {
    printf '%s' "$1" | sed \
        -e 's/&/\&amp;/g' \
        -e 's/</\&lt;/g' \
        -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' \
        -e "s/'/\&apos;/g"
}

valider_lengde() {
    FELTNAVN="$1"
    VERDI="$2"
    MAKS="$3"
    ANTALL=$(printf '%s' "$VERDI" | wc -c | tr -d ' ')

    if [ "$ANTALL" -gt "$MAKS" ]; then
        echo "$FELTNAVN er for lang (maks $MAKS tegn)."
        exit 1
    fi
}

valider_innhold() {
    T=$(trim "$T")
    K=$(trim "$K")
    X=$(trim "$X")
    O=$(trim "$O")

    valider_lengde "Pseudonym" "$N" 200
    valider_lengde "Tittel" "$T" 100
    valider_lengde "Kommentar" "$K" 1000
    valider_lengde "Tekst" "$X" 1000
    valider_lengde "Offentlig nÃ¸kkel" "$O" 200

    if [ -z "$T" ] && [ -z "$X" ]; then
        echo "Minst ett av feltene tittel eller tekst mÃ¥ fylles ut."
        exit 1
    fi
}

autentiser_bidragseier() {
    PN="$1"
    PW="$2"

    if [ -z "$PN" ] || [ -z "$PW" ]; then
        return 1
    fi

    PN_SQL=$(sql_escape "$PN")
    S=$(db_scalar "SELECT salt FROM Bidrag WHERE pseudonym='$PN_SQL';")
    if [ -z "$S" ]; then
        return 1
    fi

    H1=$(mkpasswd -m sha-256 -S "$S" "$PW" | cut -f4 -d'$')
    H2=$(db_scalar "SELECT passordhash FROM Bidrag WHERE pseudonym='$PN_SQL';")

    [ "$H1" = "$H2" ]
}

# start: Skiller mellom manglende bidrag og autentiseringsfeil i Min-visning - oppfyller F1 (identitet og flyt) og NF1 (integritet i tilbakemeldinger) (person 1 og person 2)
har_bidrag() {
    PN_SQL=$(sql_escape "$1")
    db_scalar "SELECT 1 FROM Bidrag WHERE pseudonym='$PN_SQL' LIMIT 1;"
}
# slutt: Skiller mellom manglende bidrag og autentiseringsfeil i Min-visning - oppfyller F1 (identitet og flyt) og NF1 (integritet i tilbakemeldinger) (person 1 og person 2)

# start: Tydelig feilmelding nÃ¥r Endre brukes uten eksisterende bidrag - oppfyller F1 (brukerflyt) og NF1 (integritet i tilbakemeldinger) (person 2)
svar_mangler_bidrag_for_endre() {
    echo "Ingen eksisterende bidrag Ã¥ endre. Bruk Ny."
    exit
}
# slutt: Tydelig feilmelding nÃ¥r Endre brukes uten eksisterende bidrag - oppfyller F1 (brukerflyt) og NF1 (integritet i tilbakemeldinger) (person 2)

# start: Admin-autorisering med dobbel sjekk mot pseudonym-db - oppfyller F2 (admin-visning med pseudonym) og NF1 (forsvar i dybden) (person 3 og person 5)
er_adminbruker() {
    PN="$1"
    EPOST="$2"
    PASSORD="$3"

    if [ "$PN" != "admin" ] || [ -z "$EPOST" ] || [ -z "$PASSORD" ]; then
        return 1
    fi

    XML_PN="<pseudonym>
<epost>$(xml_escape "$EPOST")</epost>
<passord>$(xml_escape "$PASSORD")</passord>
</pseudonym>"

    SVAR=$(curl -s -d "$XML_PN" "$PSEUDONYM_INTERNAL_URL")
    [ "$SVAR" = "admin" ]
}
# slutt: Admin-autorisering med dobbel sjekk mot pseudonym-db - oppfyller F2 (admin-visning med pseudonym) og NF1 (forsvar i dybden) (person 3 og person 5)

vis_offentlig_liste() {
    db_query_line "
        SELECT
            coalesce(trim(tittel), '') AS tittel,
            coalesce(trim(tekst), '') AS tekst
        FROM Bidrag
        WHERE length(trim(coalesce(tittel, ''))) > 0
           OR length(trim(coalesce(tekst, ''))) > 0
        ORDER BY rowid DESC
    "
}

vis_admin_liste() {
    db_query_line "
        SELECT
            pseudonym AS pseudonym,
            coalesce(trim(tittel), '') AS tittel,
            coalesce(trim(tekst), '') AS tekst
        FROM Bidrag
        WHERE length(trim(coalesce(tittel, ''))) > 0
           OR length(trim(coalesce(tekst, ''))) > 0
        ORDER BY rowid DESC
    "
}

vis_min_visning() {
    PN_SQL=$(sql_escape "$1")
    sqlite3 -line "$DB" "
        SELECT
            coalesce(trim(tittel), '') AS tittel,
            coalesce(trim(tekst), '') AS tekst,
            coalesce(kommentar, '') AS kommentar
        FROM Bidrag
        WHERE pseudonym='$PN_SQL'
        LIMIT 1
    "
}

# start: Steg 7-tilpasning for ciphertext og egen visning - oppfyller F1 (privat kommentar for bruker) og NF1 (sikker hÃ¥ndtering av ciphertext i backend) (person 5)
er_krypteringsmetadata() {
    printf '%s' "$1" | grep -Eq '^enc-v1\|[0-9]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$'
}

valider_kryptert_kommentar() {
    if [ -z "$K" ] && [ -n "$O" ]; then
        echo "Krypteringsmetadata kan ikke sendes uten kommentar."
        exit 1
    fi

    if [ -n "$K" ] && [ -z "$O" ]; then
        echo "Kommentar mÃ¥ sendes kryptert med metadata."
        exit 1
    fi

    if [ -n "$O" ] && ! er_krypteringsmetadata "$O"; then
        echo "Ugyldig krypteringsmetadata."
        exit 1
    fi
}

hent_bidragsfelt() {
    FELT="$1"
    PN_SQL=$(sql_escape "$2")

    case "$FELT" in
        tittel)
            SQL_FELT="coalesce(trim(tittel), '')"
            ;;
        tekst)
            SQL_FELT="coalesce(trim(tekst), '')"
            ;;
        kommentar)
            SQL_FELT="coalesce(kommentar, '')"
            ;;
        offentlig_nokkel)
            SQL_FELT="coalesce(offentlig_nokkel, '')"
            ;;
        *)
            return 1
            ;;
    esac

    db_scalar "SELECT $SQL_FELT FROM Bidrag WHERE pseudonym='$PN_SQL' LIMIT 1;"
}

vis_min_visning() {
    PN="$1"
    TITTEL_VERDI=$(hent_bidragsfelt tittel "$PN")
    TEKST_VERDI=$(hent_bidragsfelt tekst "$PN")
    KOMMENTAR_VERDI=$(hent_bidragsfelt kommentar "$PN")
    NOKKEL_VERDI=$(hent_bidragsfelt offentlig_nokkel "$PN")

    printf '<min><tittel>%s</tittel><tekst>%s</tekst><kommentar>%s</kommentar><offentlig_nokkel>%s</offentlig_nokkel></min>\n' \
        "$(xml_escape "$TITTEL_VERDI")" \
        "$(xml_escape "$TEKST_VERDI")" \
        "$(xml_escape "$KOMMENTAR_VERDI")" \
        "$(xml_escape "$NOKKEL_VERDI")"
}
# slutt: Steg 7-tilpasning for ciphertext og egen visning - oppfyller F1 (privat kommentar for bruker) og NF1 (sikker hÃ¥ndtering av ciphertext i backend) (person 5)

logg_innholdsoperasjon() {
    HAR_TITTEL=nei
    HAR_TEKST=nei
    HAR_KOMMENTAR=nei

    if [ -n "$T" ]; then HAR_TITTEL=ja; fi
    if [ -n "$X" ]; then HAR_TEKST=ja; fi
    if [ -n "$K" ]; then HAR_KOMMENTAR=ja; fi

    echo "bidrag-db $REQUEST_METHOD visning=${VISNING:-skriv} tittel=$HAR_TITTEL tekst=$HAR_TEKST kommentar=$HAR_KOMMENTAR" >&2
}
# slutt: Person 2  innhold + visninger (F1, F2, NF1)

cat <<EOF
Access-Control-Allow-Origin: https://localhost:8443
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Access-Control-Allow-Headers: Content-Type
Content-Type:text/plain;charset=utf-8

EOF

CONTENT_LENGTH=$HTTP_CONTENT_LENGTH$CONTENT_LENGTH

if [ "$REQUEST_METHOD" = "OPTIONS" ]; then
    exit
fi

if [ "$REQUEST_METHOD" = "GET" ]; then
    VISNING=$(url_param visning)

    if [ -z "$VISNING" ]; then
        VISNING=$(url_param handling)
    fi

    if [ -z "$VISNING" ] || [ "$VISNING" = "offentlig" ] || [ "$VISNING" = "Liste" ]; then
        vis_offentlig_liste
        exit
    fi

    if [ "$VISNING" = "admin" ]; then
        N=$(url_param navn)
        E=$(url_param epost)
        P=$(url_param passord)

        if er_adminbruker "$N" "$E" "$P"; then
            vis_admin_liste
        else
            echo "Ingen tilgang til admin."
        fi
        exit
    fi

    if [ "$VISNING" = "min" ] || [ "$VISNING" = "Min" ]; then
        N=$(url_param navn)
        P=$(url_param passord)

        if [ -z "$(har_bidrag "$N")" ]; then
            echo "Ingen data funnet for brukeren."
        elif autentiser_bidragseier "$N" "$P"; then
            vis_min_visning "$N"
        else
            echo "Autentisering feilet."
        fi
        exit
    fi

    echo "Ukjent visning."
    exit
fi

KR=$(head -c "$CONTENT_LENGTH")

N=$(xml_felt navn)
N=$(trim "$N") # Person 1 fjernet whitespace fra pseudonym sÃ¥ DB matcher
echo "DEBUG navn=$N" >&2
E=$(xml_felt epost)
P=$(xml_felt passord)
K=$(xml_felt kommentar)
O=$(xml_felt offentlig_nokkel)
T=$(xml_felt tittel)
X=$(xml_felt tekst)
HND=$(xml_felt handling)

logg_innholdsoperasjon

if [ "$HND" = "Min" ]; then
    if [ -z "$(har_bidrag "$N")" ]; then
        echo "Ingen data funnet for brukeren."
    elif autentiser_bidragseier "$N" "$P"; then
        vis_min_visning "$N"
    else
        echo "Autentisering feilet."
    fi
    exit
fi

if [ "$HND" = "Liste" ]; then
    vis_offentlig_liste
    exit
fi

if [ "$HND" = "Admin" ]; then
    if er_adminbruker "$N" "$E" "$P"; then
        vis_admin_liste
    else
        echo "Ingen tilgang til admin."
    fi
    exit
fi

if [ -z "$N" ]; then
    echo "Pseudonym mangler!"
    exit
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
    if [ "$HND" = "Slett" ]; then REQUEST_METHOD="DELETE"; fi
    if [ "$HND" = "Endre" ]; then REQUEST_METHOD="PUT"; fi
fi

if [ "$REQUEST_METHOD" = "POST" ]; then
    if [ -n "$P" ]; then
        valider_innhold
        # start: Steg 7-validering ved lagring av kryptert kommentar - oppfyller F1 (privat kommentar) og NF1 (sikker ciphertext-lagring) (person 5)
        valider_kryptert_kommentar
        # slutt: Steg 7-validering ved lagring av kryptert kommentar - oppfyller F1 (privat kommentar) og NF1 (sikker ciphertext-lagring) (person 5)
        N_SQL=$(sql_escape "$N")
        K_SQL=$(sql_escape "$K")
        O_SQL=$(sql_escape "$O")
        T_SQL=$(sql_escape "$T")
        X_SQL=$(sql_escape "$X")

        FINNES=$(db_query "SELECT 1 FROM Bidrag WHERE pseudonym='$N_SQL';")
        if [ -n "$FINNES" ]; then
            echo "Bidrag finnes allerede for dette pseudonymet. Bruk Endre."
            exit
        fi

        S=$(tr -dc '0-9' </dev/urandom | head -c 11)
        H=$(mkpasswd -m sha-256 -S "$S" "$P" | cut -f4 -d'$')

        db_query "
            INSERT INTO Bidrag (pseudonym, salt, passordhash, kommentar, offentlig_nokkel, tittel, tekst)
            VALUES ('$N_SQL', '$S', '$H', '$K_SQL', '$O_SQL', '$T_SQL', '$X_SQL');
        "
        echo "Bidrag lagret."
    fi
    exit
fi

N_SQL=$(sql_escape "$N")
S=$(db_scalar "SELECT salt FROM Bidrag WHERE pseudonym='$N_SQL';")
if [ -z "$S" ]; then svar_mangler_bidrag_for_endre; fi

H1=$(mkpasswd -m sha-256 -S "$S" "$P" | cut -f4 -d'$')
H2=$(db_scalar "SELECT passordhash FROM Bidrag WHERE pseudonym='$N_SQL';")

if [ "$H1" != "$H2" ]; then echo "Feil passord!" >&2 ; exit; fi

case "$REQUEST_METHOD" in
    DELETE)
        db_query "DELETE FROM Bidrag WHERE pseudonym='$N_SQL';"
        echo "Bidrag slettet."
        ;;
    PUT)
        valider_innhold
        # start: Steg 7-validering ved oppdatering av kryptert kommentar - oppfyller F1 (privat kommentar) og NF1 (sikker ciphertext-lagring) (person 5)
        valider_kryptert_kommentar
        # slutt: Steg 7-validering ved oppdatering av kryptert kommentar - oppfyller F1 (privat kommentar) og NF1 (sikker ciphertext-lagring) (person 5)
        K_SQL=$(sql_escape "$K")
        O_SQL=$(sql_escape "$O")
        T_SQL=$(sql_escape "$T")
        X_SQL=$(sql_escape "$X")

        db_query "
           UPDATE Bidrag SET
               kommentar='$K_SQL',
               offentlig_nokkel='$O_SQL',
               tittel='$T_SQL',
               tekst='$X_SQL'
           WHERE pseudonym='$N_SQL';"
        echo "Bidrag oppdatert."
        ;;
esac


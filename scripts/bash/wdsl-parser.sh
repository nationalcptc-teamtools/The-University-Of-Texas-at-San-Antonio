#!/bin/bash
# WSDL Parser
# Usage:
#   wsdl-parse http://target:3002/wsdl?wsdl
#   curl http://target:3002/wsdl?wsdl | wsdl-parse
#   wsdl-parse http://target:3002/wsdl?wsdl --no-interactive

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WSDL_FILE="/tmp/wsdl_$$.xml"
trap "rm -f $WSDL_FILE" EXIT

# Parse args — URL can be first or second arg, --no-interactive anywhere
INTERACTIVE=true
WSDL_URL=""
for arg in "$@"; do
    [[ "$arg" == "--no-interactive" ]] && INTERACTIVE=false
    [[ "$arg" == http* ]]              && WSDL_URL="$arg"
done

# Fetch from URL or read from stdin
if [ -n "$WSDL_URL" ]; then
    echo -e "${BLUE}[*] Fetching WSDL from $WSDL_URL ...${NC}"
    curl -s "$WSDL_URL" > "$WSDL_FILE"
else
    echo -e "${BLUE}[*] Reading WSDL from stdin...${NC}"
    cat > "$WSDL_FILE"
fi
[ ! -s "$WSDL_FILE" ] && echo -e "${RED}[!] No content received${NC}" && exit 1
echo -e "${GREEN}[+] WSDL received${NC}"

# Reopen stdin from terminal so interactive prompts work after piping
# Skip when non-interactive or when we fetched via URL (stdin already free)
$INTERACTIVE && [ -z "$WSDL_URL" ] && exec 0</dev/tty

TARGET_NS=$(grep -oP 'targetNamespace="\K[^"]+' "$WSDL_FILE" | head -1)
TARGET_NS="${TARGET_NS:-http://tempuri.org/}"
echo -e "${BLUE}[*] Namespace: $TARGET_NS${NC}"

echo ""
echo "========================================================"
echo "DISCOVERED OPERATIONS"
echo "========================================================"

# Pull operation names ONLY from portType block
mapfile -t OPS < <(awk '/<wsdl:portType/,/<\/wsdl:portType>/' "$WSDL_FILE" \
    | grep -oP 'operation name="\K[^"]+')

echo -e "${GREEN}[+] Found ${#OPS[@]} operations${NC}"
echo ""

for i in "${!OPS[@]}"; do
    op="${OPS[$i]}"

    # Get input message name from portType block
    input_msg=$(awk '/<wsdl:portType/,/<\/wsdl:portType>/' "$WSDL_FILE" \
        | grep -A3 "operation name=\"$op\"" \
        | grep "wsdl:input" \
        | grep -oP 'message="\K[^"]+' | head -1)
    input_msg="${input_msg##*:}"   # strip tns: prefix

    # Get element reference from message definition
    elem_ref=$(grep "wsdl:message name=\"$input_msg\"" -A5 "$WSDL_FILE" \
        | grep "wsdl:part" \
        | grep -oP 'element="\K[^"]+' | head -1)
    elem_name="${elem_ref##*:}"    # strip tns: prefix

    # If no element ref, fall back to type
    if [ -z "$elem_name" ]; then
        elem_name=$(grep "wsdl:message name=\"$input_msg\"" -A5 "$WSDL_FILE" \
            | grep "wsdl:part" \
            | grep -oP 'type="\K[^"]+' | head -1)
        elem_name="${elem_name##*:}"
    fi

    # Get SOAPAction from binding block
    soap_action=$(awk '/<wsdl:binding/,/<\/wsdl:binding>/' "$WSDL_FILE" \
        | grep -A3 "operation name=\"$op\"" \
        | grep -oP 'soapAction="\K[^"]+' | head -1)
    soap_action="${soap_action:-$op}"

    # Get params by looking at child elements inside the schema element
    mapfile -t params < <(awk "/<s:element name=\"$elem_name\"/,/<\/s:element>/" "$WSDL_FILE" \
        | grep -oP 'name="\K[^"]+' | grep -v "^$elem_name$")

    echo -e "${YELLOW}[$((i+1))] $op${NC}"
    echo "    Message   : $input_msg"
    echo "    Element   : $elem_name"
    echo "    SOAPAction: $soap_action"
    echo "    Params    : ${params[*]:-none}"
    echo ""
done

# Skip interactive section entirely if called with --no-interactive
$INTERACTIVE || { echo -e "${BLUE}[*] Done.${NC}"; exit 0; }

# Interactive template generation
while true; do
    echo "========================================================"
    read -rp "[*] Operation name for template (or 'exit'): " op_choice
    [ "$op_choice" = "exit" ] || [ "$op_choice" = "q" ] && break
    [ -z "$op_choice" ] && continue

    # Check it exists in portType
    if ! awk '/<wsdl:portType/,/<\/wsdl:portType>/' "$WSDL_FILE" \
            | grep -q "operation name=\"$op_choice\""; then
        echo -e "${RED}[!] Operation not found${NC}"
        continue
    fi

    input_msg=$(awk '/<wsdl:portType/,/<\/wsdl:portType>/' "$WSDL_FILE" \
        | grep -A3 "operation name=\"$op_choice\"" \
        | grep "wsdl:input" \
        | grep -oP 'message="\K[^"]+' | head -1)
    input_msg="${input_msg##*:}"

    elem_ref=$(grep "wsdl:message name=\"$input_msg\"" -A5 "$WSDL_FILE" \
        | grep "wsdl:part" \
        | grep -oP 'element="\K[^"]+' | head -1)
    elem_name="${elem_ref##*:}"

    if [ -z "$elem_name" ]; then
        elem_name=$(grep "wsdl:message name=\"$input_msg\"" -A5 "$WSDL_FILE" \
            | grep "wsdl:part" \
            | grep -oP 'type="\K[^"]+' | head -1)
        elem_name="${elem_name##*:}"
    fi

    soap_action=$(awk '/<wsdl:binding/,/<\/wsdl:binding>/' "$WSDL_FILE" \
        | grep -A3 "operation name=\"$op_choice\"" \
        | grep -oP 'soapAction="\K[^"]+' | head -1)
    soap_action="${soap_action:-$op_choice}"

    mapfile -t params < <(awk "/<s:element name=\"$elem_name\"/,/<\/s:element>/" "$WSDL_FILE" \
        | grep -oP 'name="\K[^"]+' | grep -v "^$elem_name$")

    echo ""
    echo -e "${GREEN}[+] Template for: $op_choice${NC}"
    echo -e "${BLUE}    SOAPAction header: \"$soap_action\"${NC}"
    echo ""

    # Build param block
    param_xml=""
    for p in "${params[@]}"; do
        param_xml+="            <$p>{$p}</$p>\n"
    done

    printf '<?xml version="1.0" encoding="utf-8"?>\n'
    printf '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="%s">\n' "$TARGET_NS"
    printf '    <soap:Body>\n'
    printf '        <tns:%s>\n' "$elem_name"
    printf '%b' "$param_xml"
    printf '        </tns:%s>\n' "$elem_name"
    printf '    </soap:Body>\n'
    printf '</soap:Envelope>\n'
    echo ""
done

echo -e "${BLUE}[*] Done.${NC}"

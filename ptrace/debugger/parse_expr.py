import re

# Match a register name: $eax, $gp0, $orig_eax
REGISTER_REGEX = re.compile(r"([a-z]+[a-z0-9_]+)")

# Make sure that the expression does not contain invalid characters
EXPR_REGEX = re.compile(r"^[()<>+*/0-9a-fA-F-]+$")

def parseExpression(process, text):
    """
    Parse an expression
    """
    # Remove spaces and convert to lower case
    text = text.strip()
    if " " in text:
        raise ValueError("Space are forbidden: %r" % text)
    text = text.lower()

    def readRegister(regs):
        name = regs.group(1)
        value = process.getreg(name)
        return str(value)

    # Replace registers by their value
    orig_text = text
    text = REGISTER_REGEX.sub(readRegister, text)

    # Replace hexadecimal by decimal
#    text = HEXADECIMAL_REGEX.sub(replaceHexadecimal, text)

    # Reject invalid characters
    if not EXPR_REGEX.match(text):
        raise ValueError("Invalid expression: %r" % orig_text)

    # Use integer division (a//b) instead of float division (a/b)
    text = text.replace("/", "//")

    # Finally, evaluate the expression
    try:
        value = eval(text)
    except SyntaxError:
        raise ValueError("Invalid expression: %r" % orig_text)
    return value


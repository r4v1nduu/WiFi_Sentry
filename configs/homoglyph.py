import re

INVISIBLE_PATTERN = re.compile(r'[\u200B-\u200F\u2060-\u206F\u00A0\u034F\uFEFF]')

HOMOGLYPHS = {
    'O': "οоΟОⲟ０Ｏ",  # Cyrillic/Greek/Coptic O's that look like Latin O
    'A': "аАⲁ",       # Cyrillic/Coptic A's that look like Latin A
    'E': "еЕℯ",       # Cyrillic E's that look like Latin E
    'I': "іІ",        # Cyrillic I's that look like Latin I
    'P': "рР",        # Cyrillic P's that look like Latin P
    'C': "сС",        # Cyrillic C's that look like Latin C
    'B': "В",         # Cyrillic V that looks like Latin B
    'H': "Н",         # Cyrillic N that looks like Latin H
    'X': "Х",         # Cyrillic X that looks like Latin X
    'K': "К",         # Cyrillic K that looks like Latin K
    'M': "М",         # Cyrillic M that looks like Latin M
}

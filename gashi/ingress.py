import re
from bs4 import BeautifulSoup, Comment
from typing import List

class DOMSanitizer:
    """
    Ingress Content Sanitizer:
    Strips presentation-layer steganography, invisible CSS tricks, HTML comments,
    and zero-width Unicode characters where Indirect Prompt Injections (IPI) hide.
    """

    STRIP_TAGS = ['script', 'style', 'noscript', 'svg', 'canvas', 'template']

    HIDDEN_CSS_PATTERNS = [
        re.compile(r'display\s*:\s*none', re.IGNORECASE),
        re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE),
        re.compile(r'font-size\s*:\s*0px?', re.IGNORECASE),
        re.compile(r'opacity\s*:\s*0', re.IGNORECASE),
        re.compile(r'color\s*:\s*(#fff|#ffffff|white|transparent)', re.IGNORECASE),
        re.compile(r'height\s*:\s*0px?', re.IGNORECASE),
        re.compile(r'position\s*:\s*absolute;\s*left\s*:\s*-[0-9]{3,}px', re.IGNORECASE), # Offscreen text
    ]

    HIDDEN_CLASS_NAMES = ['sr-only', 'hidden', 'd-none', 'invisible', 'visually-hidden']

    ZERO_WIDTH_CHARS = re.compile(r'[\u200B-\u200D\uFEFF]')

    @classmethod
    def clean(cls, raw_html: str, source_url: str = "") -> str:
        """
        Parses raw HTML and strips all non-visible or disguised injection payloads.
        Returns clean, visible text encapsulated within strict XML data boundaries.
        """
        if not raw_html or not raw_html.strip():
            return f'<untrusted_web_content integrity="tainted" source="{source_url}">\n</untrusted_web_content>'

        soup = BeautifulSoup(raw_html, "html.parser")

        # 1. Strip all HTML comments (e.g. <!-- SYSTEM OVERRIDE: ... -->)
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            comment.extract()

        # 2. Decompose script, style, and metadata tags
        for tag in soup(cls.STRIP_TAGS):
            tag.decompose()

        # 3. Strip nodes with hidden CSS styles or utility classes
        for el in list(soup.find_all(True)):
            # If element was already decomposed or has no attributes, skip
            if getattr(el, 'attrs', None) is None:
                continue

            style = el.attrs.get('style', '') or ''
            if isinstance(style, list):
                style = " ".join(style)
            style = str(style)

            class_list = el.attrs.get('class', []) or []
            class_str = " ".join(class_list).lower() if isinstance(class_list, list) else str(class_list).lower()

            # Check inline CSS steganography
            if any(pattern.search(style) for pattern in cls.HIDDEN_CSS_PATTERNS):
                el.decompose()
                continue

            # Check hidden utility classes
            if any(h_cls in class_str for h_cls in cls.HIDDEN_CLASS_NAMES):
                el.decompose()
                continue

            # Clean zero-width Unicode characters from strings
            if getattr(el, 'string', None):
                try:
                    cleaned_string = cls.ZERO_WIDTH_CHARS.sub('', str(el.string))
                    if cleaned_string != el.string:
                        el.string.replace_with(cleaned_string)
                except Exception:
                    pass

        # 4. Extract human-visible text
        clean_text = soup.get_text(separator=" ", strip=True)

        # 5. Encapsulate within strict untrusted boundary tags
        return f'<untrusted_web_content integrity="tainted" source="{source_url}">\n{clean_text}\n</untrusted_web_content>'


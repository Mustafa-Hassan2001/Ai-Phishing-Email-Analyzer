"""AI-assisted phishing email analyzer.

Typical use:

    from analyzer.pipeline import analyze
    result = analyze(open("samples/phishing_paypal.eml", "rb").read())
    print(result.score.total, result.score.level)
"""

__version__ = "1.0.0"

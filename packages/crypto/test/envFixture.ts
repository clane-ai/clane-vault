/** A .env with CRLF, a BOM, comments, export, all three quote kinds, a multi-line value, duplicates and invalid lines. */
export const FILE = String.fromCharCode(0xfeff) + '# billing\r\nexport STRIPE_KEY = \'sk_live_1\' # live\r\nPORT=3000\r\n\r\nDB="line1\nline2\\tx"\r\nPW=abc#123\r\nPW2=abc #123\r\nA=1\r\nA=2\r\nnot a line\r\nBAD="open\r\nREF=${A}\r\nE=\r\nT=`tick`';

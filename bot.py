# god_level_bot.py
import base64, zlib, binascii, marshal, dis, gzip, bz2, urllib.parse, codecs, io, ast, os, logging, re
from contextlib import redirect_stdout
try:
    from uncompyle6 import decompile
    UNCOMPYLE6_AVAILABLE = True
except ImportError:
    UNCOMPYLE6_AVAILABLE = False
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# --- Threat Analysis Module ---
THREAT_PATTERNS = {
    "HIGHLY_DANGEROUS": [
        r"os\.system", r"subprocess\.", r"os\.remove", r"os\.unlink", r"shutil\.rmtree",
        r"requests\.post", r"socket\.send", r"urllib\.request\.urlopen", r"ctypes\."
    ],
    "SUSPICIOUS": [
        r"eval", r"exec", r"open\s*\(.*['\"]w['\"].*\)", r"open\s*\(.*['\"]a['\"].*\)", # Writing or appending to files
        r"socket", r"requests\.get", r"os\.listdir", r"os\.walk", r"sys\.exit"
    ],
    "INFO": [
        r"__import__", r"getattr", r"setattr", r"globals", r"locals"
    ]
}

def analyze_threats(code):
    threats = {"HIGHLY_DANGEROUS": [], "SUSPICIOUS": [], "INFO": []}
    total_threat_score = 0
    for level, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            found = re.findall(pattern, code)
            if found:
                threats[level].extend(found)
                if level == "HIGHLY_DANGEROUS": total_threat_score += 10 * len(found)
                elif level == "SUSPICIOUS": total_threat_score += 3 * len(found)
                else: total_threat_score += 1 * len(found)
    
    if total_threat_score > 15:
        level_str = "🚨🚨🚨 অত্যন্ত বিপজ্জনক (Highly Dangerous)"
    elif total_threat_score > 5:
        level_str = "⚠️ সন্দেহজনক (Suspicious)"
    elif total_threat_score > 0:
        level_str = "🛡️ তথ্যমূলক (Informational)"
    else:
        level_str = "✅ নিরাপদ মনে হচ্ছে (Seems Safe)"

    report = f"**বিপদমাত্রা:** {level_str}\n"
    for level, found_items in threats.items():
        if found_items:
            report += f"\n- **{level}:** `{', '.join(set(found_items))}`"
    return report

# --- AST Deobfuscation Module ---
class AdvancedASTSimplifier(ast.NodeTransformer):
    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Add) and isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
            if isinstance(node.left.value, str) and isinstance(node.right.value, str):
                return ast.Constant(value=node.left.value + node.right.value)
        self.generic_visit(node)
        return node

    def visit_List(self, node):
        # Simplifies [chr(104), chr(101)] -> "he" (if it's part of a join)
        # This part is complex, for now we keep it simple. A more advanced version would track variable assignments.
        is_all_chr_calls = True
        char_codes = []
        for elt in node.elts:
            if isinstance(elt, ast.Call) and isinstance(elt.func, ast.Name) and elt.func.id == 'chr' and isinstance(elt.args[0], ast.Constant):
                char_codes.append(elt.args[0].value)
            else:
                is_all_chr_calls = False
                break
        if is_all_chr_calls:
            try:
                return ast.Constant(value=''.join(map(chr, char_codes)))
            except:
                pass
        return node
        
def simplify_source_code(source_code):
    try:
        tree = ast.parse(source_code)
        simplifier = AdvancedASTSimplifier()
        simplified_tree = simplifier.visit(tree)
        return ast.unparse(simplified_tree)
    except Exception:
        return source_code

# --- Decompilation & Decoding Engine ---
def decompile_marshal(data_bytes):
    if UNCOMPYLE6_AVAILABLE:
        try:
            out = io.StringIO()
            decompile(3.9, data_bytes, out) # Python 3.9
            source_code = out.getvalue()
            if source_code and not source_code.startswith("# uncompyle6 error"):
                 return source_code.encode('utf-8'), "Marshal (Decompiled)"
        except Exception:
            pass
    # Fallback to disassembly
    try:
        code_obj = marshal.loads(data_bytes)
        s = io.StringIO()
        with redirect_stdout(s): dis.dis(code_obj)
        return s.getvalue().encode('utf-8'), "Marshal (Disassembled)"
    except Exception: return None

DECODERS = [
    (lambda d: (base64.b64decode(d), "Base64")), (lambda d: (zlib.decompress(d), "Zlib")),
    decompile_marshal, (lambda d: (gzip.decompress(d), "Gzip")),
    (lambda d: (binascii.unhexlify(d), "Hex")), (lambda d: (base64.b32decode(d), "Base32")),
    (lambda d: (bz2.decompress(d), "Bz2")), (lambda d: (codecs.decode(d, 'rot_13').encode('utf-8'), "ROT13"))
]

def god_level_decode(initial_data: str) -> str:
    try:
        current_data = ast.literal_eval(initial_data)
    except Exception:
        current_data = initial_data

    if isinstance(current_data, str):
        current_data = current_data.encode('utf-8', errors='ignore')

    decoding_steps, max_iterations = [], 30
    for i in range(max_iterations):
        decoded_in_this_iteration = False
        for decoder_func in DECODERS:
            try:
                result = decoder_func(current_data)
                if result:
                    new_data, method_name = result
                    decoding_steps.append(f"✅ ধাপ {len(decoding_steps) + 1}: `{method_name}` সফল হয়েছে।")
                    current_data, decoded_in_this_iteration = new_data, True
                    break
            except Exception: continue
        if not decoded_in_this_iteration: break

    if not decoding_steps:
        return "❌ চূড়ান্ত ব্যর্থতা। এই কোডটি পরিচিত কোনো পদ্ধতিতে ডিকোড করা সম্ভব হয়নি। এটি সম্ভবত কাস্টম এনক্রিপশন বা একটি বাণিজ্যিক প্রোটেক্টর (যেমন PyArmor) দ্বারা সুরক্ষিত।"
    
    report = "🔬 **বিশ্লেষণ রিপোর্ট:**\n" + "\n".join(decoding_steps)
    final_code_str = current_data.decode('utf-8', errors='ignore')

    simplified_code = simplify_source_code(final_code_str)
    if simplified_code != final_code_str:
        report += f"\n✅ ধাপ {len(decoding_steps)+1}: `AST Simplification` সফল হয়েছে।"
        final_code_str = simplified_code
    
    report += "\n\n" + ("-"*20) + "\n\n"
    report += "🚨 **থ্রেট অ্যানালাইসিস:**\n" + analyze_threats(final_code_str)
    report += "\n\n" + ("-"*20) + "\n\n"
    report += f"**✨ চূড়ান্ত ডিকোড করা কোড:**\n```python\n{final_code_str}\n```"
    return report

# --- Telegram Bot Handlers ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_html(
        f"স্বাগতম!\n\nএটি **God-Level Deobfuscator & Threat Analyzer**। আমাকে যেকোনো জটিল পাইথন কোড দিন, আমি সেটির রহস্য ভেদ করে তার ভেতরের উদ্দেশ্য বিশ্লেষণ করে দেবো।"
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_code = update.message.text
    if len(user_code) > 15000:
        await update.message.reply_text("❌ ইনপুটটি খুব দীর্ঘ। অনুগ্রহ করে ছোট কোড দিন।")
        return
        
    await update.message.reply_text("আপনার কোড গভীরভাবে বিশ্লেষণ করা হচ্ছে... এটি একটি জটিল প্রক্রিয়া, কিছুক্ষণ সময় লাগতে পারে।")
    decoded_result = god_level_decode(user_code)
    
    if len(decoded_result) > 4096:
        for i in range(0, len(decoded_result), 4000):
             await update.message.reply_markdown(decoded_result[i:i+4000])
    else:
        await update.message.reply_markdown(decoded_result)

def main():
    if not TELEGRAM_TOKEN:
        print("ত্রুটি: TELEGRAM_TOKEN এনভায়রনমেন্ট ভেরিয়েবল সেট করা হয়নি।")
        return

    application = Application.builder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("God-Level অ্যানালিস্ট বট চলছে...")
    application.run_polling()

if __name__ == '__main__':
    main()

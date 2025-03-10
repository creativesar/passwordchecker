import re
import random
import string
import streamlit as st
from typing import Tuple
import math
from pathlib import Path
import hashlib
import requests
import json
import zxcvbn
import time  
import pyperclip 

def calculate_entropy(password: str) -> float:
    char_set_size = 0
    if re.search(r'[a-z]', password): char_set_size += 26
    if re.search(r'[A-Z]', password): char_set_size += 26
    if re.search(r'\d', password): char_set_size += 10
    if re.search(r'[!@#$%^&*]', password): char_set_size += 8
    if re.search(r'[^a-zA-Z0-9!@#$%^&*]', password): char_set_size += 33  # Other special chars
    return len(password) * math.log2(char_set_size) if char_set_size else 0

def check_password_leaked(password: str) -> Tuple[bool, int]:
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for hash_suffix, count in hashes:
                if hash_suffix == suffix:
                    return True, int(count)
    except:
        pass
    return False, 0

def has_sequential_chars(password: str) -> bool:
    sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789']
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3].lower() in password.lower():
                return True
    return False

def initialize_password_history():
    if 'password_history' not in st.session_state:
        st.session_state.password_history = {}
    if 'generated_passwords' not in st.session_state:
        st.session_state.generated_passwords = []

def get_password_age(password_hash: str) -> int:
    initialize_password_history()
    current_time = int(time.time())
    return current_time - st.session_state.password_history.get(password_hash, current_time)

def update_password_history(password_hash: str):
    initialize_password_history()
    st.session_state.password_history[password_hash] = int(time.time())

# Load a better word list for memorable passwords
def load_word_list():
    common_words = [
        "apple", "banana", "orange", "grape", "kiwi", "melon", "peach", "plum",
        "tiger", "lion", "eagle", "shark", "whale", "dolphin", "elephant", "giraffe",
        "mountain", "river", "ocean", "forest", "desert", "valley", "canyon", "island",
        "happy", "brave", "clever", "mighty", "gentle", "swift", "bright", "calm",
        "silver", "golden", "crystal", "diamond", "emerald", "sapphire", "ruby", "amber"
    ]
    return common_words

def check_password_strength(password: str) -> Tuple[int, str, list]:
    score = 0
    feedback = []
    
    # Add zxcvbn analysis
    zxcvbn_result = zxcvbn.zxcvbn(password)
    score += zxcvbn_result['score']
    
    # Add feedback from zxcvbn
    if zxcvbn_result['feedback']['warning']:
        feedback.append(zxcvbn_result['feedback']['warning'])
    for suggestion in zxcvbn_result['feedback']['suggestions']:
        feedback.append(suggestion)
    
    # Check length with more granular scoring
    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long (12+ recommended)")
    
    # Check for keyboard patterns
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456']
    if any(pattern.lower() in password.lower() for pattern in keyboard_patterns):
        score -= 2
        feedback.append("Avoid keyboard patterns (e.g., 'qwerty', 'asdfgh')")
    
    # Check for common substitutions
    substitutions = [('a', '@'), ('i', '1'), ('o', '0'), ('s', '$'), ('e', '3')]
    sub_count = 0
    for char, sub in substitutions:
        if char in password.lower() and sub in password:
            sub_count += 1
    if sub_count >= 2:
        score -= 1
        feedback.append("Using common character substitutions makes password predictable")
    
    # Check for dates and years
    if re.search(r'19\d{2}|20\d{2}', password):
        score -= 1
        feedback.append("Avoid using years in your password")
    if re.search(r'(0[1-9]|1[0-2])[/-]([0-2][0-9]|3[01])', password):  # Fixed parentheses
        score -= 1
        feedback.append("Avoid using dates in your password")
        
    # Check for personal information patterns
    if re.search(r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)', password.lower()):
        score -= 1
        feedback.append("Avoid using month names in your password")
        
    # Check for common names
    common_names = ["john", "mary", "mike", "david", "sarah", "james", "linda", "robert", "lisa"]
    if any(name in password.lower() for name in common_names):
        score -= 1
        feedback.append("Avoid using common names in your password")

    # Enhanced sequential character check
    sequences = [
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3].lower() in password.lower() or seq[i:i+3].lower()[::-1] in password.lower():
                score -= 1
                feedback.append("Avoid sequential characters (including keyboard patterns)")
                break
    
    # Check for uppercase and lowercase
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Include both uppercase and lowercase letters")
    
    # Enhanced digit check
    digit_count = len(re.findall(r'\d', password))
    if digit_count >= 2:
        score += 2
    elif digit_count == 1:
        score += 1
        feedback.append("Consider using more than one number")
    else:
        feedback.append("Include at least one number")
    
    # Enhanced special character check
    special_chars = len(re.findall(r'[!@#$%^&*]', password))
    if special_chars >= 2:
        score += 2
    elif special_chars == 1:
        score += 1
        feedback.append("Consider using more special characters")
    else:
        feedback.append("Include at least one special character (!@#$%^&*)")
    
    # Check for repeating characters
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("Avoid repeating characters (e.g., 'aaa')")
    
    # Check for dictionary words
    word_pattern = re.compile(r'^[a-zA-Z]{4,}$')
    words = password.split()
    for word in words:
        if word_pattern.match(word):
            score -= 1
            feedback.append("Avoid using dictionary words")
            break
    
    # Check for password leaks
    is_leaked, leak_count = check_password_leaked(password)
    if is_leaked:
        score -= 2
        feedback.append(f"⚠️ This password has been exposed in {leak_count:,} data breaches!")

    # Enhanced entropy check
    entropy = calculate_entropy(password)
    if entropy > 80:
        score += 2
    elif entropy > 60:
        score += 1
    
    # Determine strength level based on final score
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    elif score <= 6:
        strength = "Strong"
    else:
        strength = "Very Strong"
        
    # Check password age if it exists in history
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    update_password_history(password_hash)
    password_age = get_password_age(password_hash) / (24 * 3600)  # Convert to days
    if password_age > 90:  # 90 days threshold
        feedback.append(f"⚠️ Password is {int(password_age)} days old. Consider updating it.")
    
    return score, strength, feedback

def generate_password(length: int = 16, include_symbols: bool = True, 
                     avoid_similar: bool = True, pattern: str = "random") -> str:
    if pattern == "memorable":
        words = load_word_list()
        password = ''.join(random.choice(words).capitalize() for _ in range(3))
        password += str(random.randint(100, 999))
        if include_symbols:
            password += random.choice("!@#$%^&*")
        return password
    
    if length < 12:
        length = 12
    
    # Avoid similar looking characters if requested
    chars = string.ascii_letters + string.digits
    if avoid_similar:
        chars = chars.translate(str.maketrans('', '', 'Il1O0'))
    
    symbols = "!@#$%^&*" if include_symbols else ""
    characters = chars + symbols
    
    # Ensure at least one of each required character type
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits)
    ]
    
    if include_symbols:
        password.append(random.choice(symbols))
        
    # Fill the rest with random characters
    for _ in range(length - len(password)):
        password.append(random.choice(characters))
    
    # Shuffle the password multiple times for better randomization
    for _ in range(3):
        random.shuffle(password)
    return ''.join(password)

# Add after the existing imports
from datetime import datetime
import string
import random

def get_password_pronunciation(password: str) -> str:
    pronunciation = []
    for char in password:
        if char.isalpha():
            pronunciation.append(char)
        elif char.isdigit():
            pronunciation.append(f"number {char}")
        elif char in string.punctuation:
            char_pronunciations = {
                '!': 'exclamation',
                '@': 'at',
                '#': 'hash',
                '$': 'dollar',
                '%': 'percent',
                '^': 'caret',
                '&': 'ampersand',
                '*': 'star'
            }
            pronunciation.append(char_pronunciations.get(char, char))
    return " ".join(pronunciation)

def main():
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔒",
                       layout="wide")
    
    # Define strength emoji dictionary at the start
    strength_emoji = {
        "Weak": "⚠️",
        "Moderate": "📊",
        "Strong": "💪",
        "Very Strong": "🔒"
    }
    
    # Add custom CSS with all styles in one place
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #ff0000, #ffa500, #00ff00);
        }
        .password-card {
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .feedback-item {
            margin: 5px 0;
            padding: 5px;
            border-radius: 5px;
        }
        .copy-btn {
            display: inline-block;
            padding: 5px 10px;
            background-color: #4CAF50;
            color: white;
            border-radius: 5px;
            cursor: pointer;
            margin-left: 10px;
        }
        @keyframes strengthPulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        .strength-indicator {
            padding: 10px;
            border-radius: 8px;
            margin: 10px 0;
            animation: strengthPulse 2s infinite;
            text-align: center;
            font-weight: bold;
        }
        .password-stats {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 10px 0;
        }
        .pronunciation-guide {
            background: #f0f2f6;
            padding: 10px;
            border-radius: 8px;
            font-family: monospace;
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🔒 Password Strength Analyzer")
    st.write("Check how strong your password is and generate secure passwords!")
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Password Checker", "Password Generator", "Password Tips"])
    
    with tab1:
        col1, col2 = st.columns([3, 1])
        with col1:
            password = st.text_input("Enter your password", type="password")
            # Add password length indicator
            if password:
                st.text(f"Password length: {len(password)} characters")
        
        if password:
            score, strength, feedback = check_password_strength(password)
            
            # Add crack time estimation
            zxcvbn_result = zxcvbn.zxcvbn(password)
            crack_time = zxcvbn_result['crack_times_display']['offline_fast_hashing_1e10_per_second']
            
            # Normalize score for progress bar (0-100%)
            normalized_score = min(100, max(0, (score / 10) * 100))
            
            # Color coding based on strength
            if strength == "Weak":
                bar_color = "red"
            elif strength == "Moderate":
                bar_color = "orange"
            elif strength == "Strong":
                bar_color = "lightgreen"
            else:
                bar_color = "green"
                
            st.markdown(f"### {strength_emoji.get(strength, '')} Password Strength: {strength}")
            st.progress(normalized_score/100)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.info(f"🔢 Entropy: {calculate_entropy(password):.1f} bits")
            with col2:
                st.info(f"⚡ Estimated crack time: {crack_time}")
            with col3:
                is_leaked, leak_count = check_password_leaked(password)
                if is_leaked:
                    st.error(f"⚠️ Found in {leak_count:,} data breaches!")
                else:
                    st.success("✅ Not found in known data breaches")
            
            # Display feedback with better formatting
            if feedback:
                st.markdown("### Feedback")
                for item in feedback:
                    st.markdown(f"- {item}")
    
    with tab2:
        st.markdown("### Generate a Strong Password")
        
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("Length", 12, 32, 16)
            include_symbols = st.checkbox("Include Symbols", value=True)
        with col2:
            avoid_similar = st.checkbox("Avoid Similar Characters", value=True)
            pattern = st.selectbox("Password Pattern", ["random", "memorable"])
            
        if st.button("Generate Strong Password", key="generate_btn"):
            generated_password = generate_password(length, include_symbols, avoid_similar, pattern)
            
            # Store in history (limit to last 5)
            initialize_password_history()
            st.session_state.generated_passwords.append(generated_password)
            if len(st.session_state.generated_passwords) > 5:
                st.session_state.generated_passwords.pop(0)
            
            # Display password with copy button
            col1, col2 = st.columns([3, 1])
            with col1:
                st.code(generated_password)
            with col2:
                if st.button("📋 Copy", key="copy_btn"):
                    try:
                        pyperclip.copy(generated_password)
                        st.success("Copied to clipboard!")
                    except:
                        st.error("Could not copy to clipboard. Please install pyperclip.")
            
            # Add password confirmation field
            st.text_input("Confirm by typing the password:", key="confirm_password",
                         help="Type the generated password to ensure you've copied it correctly")
            
            # Show recent generated passwords
            if st.session_state.generated_passwords:
                with st.expander("Recent Generated Passwords"):
                    st.warning("⚠️ For security, these are only stored temporarily in your session")
                    for idx, past_pwd in enumerate(reversed(st.session_state.generated_passwords[:-1]), 1):
                        st.code(f"Previous {idx}: {past_pwd}")
            
            score, strength, _ = check_password_strength(generated_password)
            
            # Show password statistics
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"Password Entropy: {calculate_entropy(generated_password):.2f} bits")
                st.success(f"Password Strength: {strength}")
            with col2:
                zxcvbn_result = zxcvbn.zxcvbn(generated_password)
                st.info(f"Crack time: {zxcvbn_result['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
    
    with tab3:
        st.markdown("### Password Security Tips")
        st.markdown("""
        #### Creating Strong Passwords
        - Use a minimum of 12 characters, preferably 16+
        - Mix uppercase, lowercase, numbers, and special characters
        - Avoid personal information (names, dates, etc.)
        - Don't use dictionary words or common patterns
        
        #### Best Practices
        - Use a different password for each account
        - Change passwords regularly (every 90 days)
        - Consider using a password manager
        - Enable two-factor authentication when available
        
        #### Common Mistakes to Avoid
        - Using sequential characters (abc123, qwerty)
        - Simple character substitutions (p@ssw0rd)
        - Writing passwords down or sharing them
        - Using the same password across multiple sites
        """)

if __name__ == "__main__":
    main()
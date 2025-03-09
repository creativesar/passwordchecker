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
import time  # Add time module import
import pandas as pd
from datetime import datetime
import plotly.express as px

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

def get_password_age(password_hash: str) -> int:
    initialize_password_history()
    current_time = int(time.time())
    return current_time - st.session_state.password_history.get(password_hash, current_time)

def update_password_history(password_hash: str):
    initialize_password_history()
    st.session_state.password_history[password_hash] = int(time.time())

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
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long (12+ recommended)")
    
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
    
    # Check for sequential characters
    if has_sequential_chars(password):
        score -= 1
        feedback.append("Avoid sequential characters (e.g., 'abc', '123')")
    
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
                     avoid_similar: bool = True, pattern: str = "random",
                     word_count: int = 4) -> str:
    if pattern == "memorable":
        # Enhanced memorable password generation
        with open("wordlist.txt", "r") as f:
            words = [word.strip() for word in f.readlines()]
        password = ''.join(random.choice(words).capitalize() for _ in range(word_count))
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

def main():
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔒",
                       layout="wide")
    
    # Add sidebar
    with st.sidebar:
        st.header("📊 Password Statistics")
        if 'password_history' in st.session_state:
            df = pd.DataFrame(
                [(k, v) for k, v in st.session_state.password_history.items()],
                columns=['Password Hash', 'Timestamp']
            )
            df['Date'] = pd.to_datetime(df['Timestamp'], unit='s')
            st.write(f"Total Passwords Checked: {len(df)}")
            
            # Show password check history
            fig = px.line(df, x='Date', y=df.index, 
                         title='Password Check History')
            st.plotly_chart(fig, use_container_width=True)
        
        st.header("🛡️ Password Policy")
        st.write("""
        Strong passwords should:
        - Be at least 12 characters long
        - Include uppercase and lowercase letters
        - Include numbers and symbols
        - Avoid common patterns and words
        - Be unique for each account
        - Be changed every 90 days
        """)
    
    # Main content
    st.title("🔒 Advanced Password Strength Analyzer")
    st.write("Check how strong your password is and generate secure passwords!")
    
    tab1, tab2, tab3 = st.tabs(["Password Checker", "Password Generator", "Security Tips"])
    
    with tab1:
        col1, col2 = st.columns([3, 1])
        with col1:
            password = st.text_input("Enter your password", type="password")
        with col2:
            show_password = st.checkbox("Show password")
            if show_password:
                st.code(password)
        
        if password:
            # Add password composition analysis
            char_types = {
                "Uppercase": len(re.findall(r'[A-Z]', password)),
                "Lowercase": len(re.findall(r'[a-z]', password)),
                "Numbers": len(re.findall(r'\d', password)),
                "Symbols": len(re.findall(r'[!@#$%^&*]', password))
            }
            
            st.write("Password Composition:")
            fig = px.pie(values=list(char_types.values()),
                        names=list(char_types.keys()),
                        title="Character Distribution")
            st.plotly_chart(fig, use_container_width=True)
    
    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            pattern = st.selectbox("Generation Pattern", 
                                 ["random", "memorable", "phrase"])
            length = st.slider("Password Length", 12, 32, 16)
        with col2:
            include_symbols = st.checkbox("Include Symbols", value=True)
            avoid_similar = st.checkbox("Avoid Similar Characters", value=True)
            if pattern == "memorable":
                word_count = st.slider("Number of Words", 3, 6, 4)
    
    with tab3:
        st.header("🔐 Password Security Best Practices")
        st.write("""
        1. Use a different password for each account
        2. Enable two-factor authentication when available
        3. Use a password manager
        4. Regularly check for password breaches
        5. Avoid using personal information
        6. Don't share passwords
        7. Use passphrases instead of single words
        """)
        
        # Add password breach statistics
        st.header("📈 Password Breach Statistics")
        if 'breach_count' not in st.session_state:
            st.session_state.breach_count = 0
        st.metric("Passwords Found in Breaches", 
                 f"{st.session_state.breach_count:,}")

if __name__ == "__main__":
    main()
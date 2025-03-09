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

def check_password_strength(password: str) -> Tuple[int, str, list]:
    score = 0
    feedback = []
    
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
        
    return score, strength, feedback

def generate_password(length: int = 16, include_symbols: bool = True, avoid_similar: bool = True) -> str:
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
    st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔒")
    
    # Add custom CSS for strength meter
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #ff0000, #ffa500, #00ff00);
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🔒 Password Strength Analyzer")
    st.write("Check how strong your password is and generate secure passwords!")
    
    tab1, tab2 = st.tabs(["Password Checker", "Password Generator"])
    
    with tab1:
        col1, col2 = st.columns([3, 1])
        with col1:
            password = st.text_input("Enter your password", type="password")
        with col2:
            show_password = st.checkbox("Show password")
            if show_password:
                st.code(password)
        
        if password:
            score, strength, feedback = check_password_strength(password)
            
            # Enhanced strength display
            entropy = calculate_entropy(password)
            col1, col2 = st.columns(2)
            with col1:
                strength_display = f"{strength_emoji.get(strength, '')} Strength: {strength}"
                if strength == "Weak":
                    st.error(strength_display)
                elif strength == "Moderate":
                    st.warning(strength_display)
                else:
                    st.success(strength_display)
            with col2:
                st.info(f"🔢 Entropy: {entropy:.1f} bits")
            
            # Display progress bar
            st.progress(min(score/8, 1.0))
            
            if feedback:
                st.write("Suggestions for improvement:")
                for suggestion in feedback:
                    st.write("• " + suggestion)
    
    with tab2:
        col1, col2, col3 = st.columns(3)
        with col1:
            length = st.slider("Length", 12, 32, 16)
        with col2:
            include_symbols = st.checkbox("Symbols", value=True)
        with col3:
            avoid_similar = st.checkbox("Avoid Similar", value=True)
            
        if st.button("Generate Strong Password"):
            generated_password = generate_password(length, include_symbols)
            st.code(generated_password)
            score, strength, _ = check_password_strength(generated_password)
            entropy = calculate_entropy(generated_password)
            st.info(f"Password Entropy: {entropy:.2f} bits")
            st.success(f"Password Strength: {strength}")
    
    strength_emoji = {
        "Weak": "⚠️",
        "Moderate": "📊",
        "Strong": "💪",
        "Very Strong": "🔒"
    }

if __name__ == "__main__":
    main()
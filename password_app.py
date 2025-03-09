import re
import random
import string
import streamlit as st
from typing import Tuple
import math
from pathlib import Path

def calculate_entropy(password: str) -> float:
    char_set_size = 0
    if re.search(r'[a-z]', password): char_set_size += 26
    if re.search(r'[A-Z]', password): char_set_size += 26
    if re.search(r'\d', password): char_set_size += 10
    if re.search(r'[!@#$%^&*]', password): char_set_size += 8
    return len(password) * math.log2(char_set_size) if char_set_size else 0

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
    
    # Calculate entropy bonus
    entropy = calculate_entropy(password)
    if entropy > 60:
        score += 1
    
    # Check for common passwords
    common_passwords = {'password123', 'admin123', '12345678', 'qwerty123'}
    if password.lower() in common_passwords:
        score = 1
        feedback.append("This is a commonly used password. Please choose something more unique")
    
    # Updated strength determination
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    elif score <= 6:
        strength = "Strong"
    else:
        strength = "Very Strong"
        
    return score, strength, feedback

def generate_password(length: int = 16, include_symbols: bool = True) -> str:
    if length < 12:
        length = 12  # Enforce minimum length
        
    chars = string.ascii_letters + string.digits
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
    
    st.title("🔒 Password Strength Analyzer")
    st.write("Check how strong your password is and generate secure passwords!")
    
    tab1, tab2 = st.tabs(["Password Checker", "Password Generator"])
    
    with tab1:
        password = st.text_input("Enter your password", type="password")
        
        if password:
            score, strength, feedback = check_password_strength(password)
            
            # Display strength with color coding and emoji
            strength_emoji = {"Weak": "⚠️", "Moderate": "📊", "Strong": "💪", "Very Strong": "🔒"}
            strength_display = f"{strength_emoji.get(strength, '')} Password Strength: {strength}"
            
            if strength == "Weak":
                st.error(strength_display)
            elif strength == "Moderate":
                st.warning(strength_display)
            elif strength == "Strong":
                st.success(strength_display)
            else:
                st.success(strength_display)
            
            # Display entropy
            entropy = calculate_entropy(password)
            st.info(f"Password Entropy: {entropy:.2f} bits")
            
            # Display progress bar
            st.progress(min(score/8, 1.0))
            
            if feedback:
                st.write("Suggestions for improvement:")
                for suggestion in feedback:
                    st.write("• " + suggestion)
    
    with tab2:
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("Password Length", 12, 32, 16)
        with col2:
            include_symbols = st.checkbox("Include Symbols", value=True)
            
        if st.button("Generate Strong Password"):
            generated_password = generate_password(length, include_symbols)
            st.code(generated_password)
            score, strength, _ = check_password_strength(generated_password)
            entropy = calculate_entropy(generated_password)
            st.info(f"Password Entropy: {entropy:.2f} bits")
            st.success(f"Password Strength: {strength}")

if __name__ == "__main__":
    main()
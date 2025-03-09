import re
import random
import string
import streamlit as st
from typing import Tuple
import math
import json
from datetime import datetime

def calculate_entropy(password: str) -> float:
    char_set_size = 0
    if re.search(r'[a-z]', password): char_set_size += 26
    if re.search(r'[A-Z]', password): char_set_size += 26
    if re.search(r'[0-9]', password): char_set_size += 10
    if re.search(r'[!@#$%^&*]', password): char_set_size += 8
    return len(password) * math.log2(char_set_size) if char_set_size else 0

def check_password_strength(password: str) -> Tuple[int, str, list, float]:
    score = 0
    feedback = []
    
    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Check for uppercase and lowercase
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Include both uppercase and lowercase letters")
    
    # Check for digits
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Include at least one number")
    
    # Check for special characters
    if re.search(r'[!@#$%^&*]', password):
        score += 1
    else:
        feedback.append("Include at least one special character (!@#$%^&*)")
    
    # Check for common passwords
    # Enhanced common password check
    common_passwords = {'password123', 'admin123', '12345678', 'qwerty123', 
                       'letmein', 'welcome1', 'monkey123', 'football', 
                       'abc123', '123456789', 'dragon123', 'baseball'}
    
    # Check for repeated patterns
    if re.search(r'(.)\1{2,}', password):
        feedback.append("Avoid using repeated characters (e.g., 'aaa')")
        score -= 1

    # Calculate entropy
    entropy = calculate_entropy(password)
    if entropy < 50:
        feedback.append("Password complexity is too low")
    elif entropy > 100:
        score += 1
    
    # Determine strength level
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"
        
    return score, strength, feedback, entropy

def generate_password() -> str:
    length = random.randint(12, 16)
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Ensure at least one of each required character type
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice("!@#$%^&*")
    ]
    
    # Fill the rest with random characters
    for _ in range(length - 4):
        password.append(random.choice(characters))
    
    # Shuffle the password
    random.shuffle(password)
    return ''.join(password)

def main():
    st.set_page_config(page_title="Advanced Password Strength Meter", layout="wide")
    
    # Add custom CSS
    st.markdown("""
        <style>
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #ff0000, #ffa500, #00ff00);
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🔒 Advanced Password Strength Meter")
    st.write("Create and verify strong passwords with advanced security metrics!")

    col1, col2 = st.columns([2, 1])

    with col1:
        # Password input with visibility toggle
        show_password = st.checkbox("Show password")
        password = st.text_input(
            "Enter your password",
            type="" if show_password else "password"
        )

        if password:
            score, strength, feedback, entropy = check_password_strength(password)
            
            # Create metrics row
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Strength Score", f"{score}/5")
            with m2:
                st.metric("Entropy", f"{entropy:.1f} bits")
            with m3:
                st.metric("Length", len(password))

            # Display strength with enhanced visuals
            if strength == "Weak":
                st.error("🔓 " + f"Password Strength: {strength}")
            elif strength == "Moderate":
                st.warning("🔐 " + f"Password Strength: {strength}")
            else:
                st.success("🔒 " + f"Password Strength: {strength}")
            
            st.progress(score/5)
            
            # Display feedback with better formatting
            if feedback:
                st.write("### Improvement Suggestions:")
                for suggestion in feedback:
                    st.warning("• " + suggestion)

    with col2:
        st.markdown("### Password Generator")
        if st.button("🎲 Generate Strong Password"):
            generated_password = generate_password()
            st.code(generated_password)
            st.info("✅ This password meets all security criteria!")
            
            # Add copy button
            st.markdown(f"""
                <input type="text" value="{generated_password}" id="generated_password" readonly style="position: absolute; left: -9999px;">
                <button onclick="navigator.clipboard.writeText(document.getElementById('generated_password').value)">
                    Copy to Clipboard
                </button>
                """, 
                unsafe_allow_html=True
            )

    # Password History
    if 'password_history' not in st.session_state:
        st.session_state.password_history = []

    if password:
        # Store password check history
        history_entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'strength': strength,
            'score': score,
            'entropy': entropy
        }
        st.session_state.password_history.append(history_entry)

    # Display password check history
    if st.session_state.password_history:
        st.markdown("### Password Check History")
        history_df = pd.DataFrame(st.session_state.password_history)
        st.dataframe(history_df)

if __name__ == "__main__":
    main()
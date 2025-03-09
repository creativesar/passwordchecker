import re
import random
import string
import streamlit as st
from typing import Tuple

def check_password_strength(password: str) -> Tuple[int, str, list]:
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
    common_passwords = {'password123', 'admin123', '12345678', 'qwerty123'}
    if password.lower() in common_passwords:
        score = 1
        feedback.append("This is a commonly used password. Please choose something more unique")
    
    # Determine strength level
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"
        
    return score, strength, feedback

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
    st.title("Password Strength Meter")
    st.write("Check how strong your password is!")
    
    # Password input
    password = st.text_input("Enter your password", type="password")
    
    if password:
        score, strength, feedback = check_password_strength(password)
        
        # Display strength with color coding
        if strength == "Weak":
            st.error(f"Password Strength: {strength}")
        elif strength == "Moderate":
            st.warning(f"Password Strength: {strength}")
        else:
            st.success(f"Password Strength: {strength}")
        
        # Display progress bar
        st.progress(score/5)
        
        # Display feedback if not strong
        if strength != "Strong":
            st.write("Suggestions for improvement:")
            for suggestion in feedback:
                st.write("• " + suggestion)
        else:
            st.success("Great! Your password meets all security criteria!")
    
    # Password generator section
    st.markdown("---")
    st.subheader("Need a Strong Password?")
    if st.button("Generate Strong Password"):
        generated_password = generate_password()
        st.code(generated_password)
        st.info("This generated password meets all security criteria!")

if __name__ == "__main__":
    main()
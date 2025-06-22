import os
import base64
import mimetypes
import tkinter as tk
from tkinter import messagebox, filedialog
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser
from langchain_openai import ChatOpenAI

# Load environment variables
load_dotenv()
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Initialize LangChain model
model = ChatOpenAI(model="gpt-3.5-turbo")
email_prompt = ChatPromptTemplate.from_messages([
    ("system", "You are an AI assistant helping to write emails."),
    ("human", "Write a professional email about {subject} with the following details: {details}.")
])
email_chain = email_prompt | model | StrOutputParser()

# File path for attachment
attachment_file_path = None

def authenticate_gmail():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("gmail.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def send_email(to_email, subject, message_body, attachment_path=None):
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    msg = MIMEMultipart()
    msg["to"] = to_email
    msg["subject"] = subject
    msg.attach(MIMEText(message_body, "plain"))

    if attachment_path:
        content_type, encoding = mimetypes.guess_type(attachment_path)
        main_type, sub_type = content_type.split('/', 1)
        with open(attachment_path, "rb") as f:
            file_data = f.read()
        file_name = os.path.basename(attachment_path)
        part = MIMEBase(main_type, sub_type)
        part.set_payload(file_data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={file_name}")
        msg.attach(part)

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = {"raw": raw}
    try:
        send_message = service.users().messages().send(userId="me", body=message).execute()
        messagebox.showinfo("✅ Success", f"Email sent to {to_email}\nMessage ID: {send_message['id']}")
    except HttpError as error:
        messagebox.showerror("❌ Error", f"An error occurred: {error}")

def browse_attachment():
    global attachment_file_path
    file_path = filedialog.askopenfilename()
    if file_path:
        attachment_file_path = file_path
        attachment_label.config(text=os.path.basename(file_path), fg="#198754")

def generate_and_send_email():
    recipient_email = recipient_entry.get()
    subject = subject_entry.get()
    details = details_text.get("1.0", tk.END).strip()

    if not recipient_email or not subject or not details:
        messagebox.showerror("❌ Error", "All fields are required!")
        return

    try:
        generated_email = email_chain.invoke({"subject": subject, "details": details})

        preview_win = tk.Toplevel(root)
        preview_win.title("✍️ Edit Email Before Sending")
        preview_win.geometry("560x500")
        preview_win.configure(bg="#ffffff")
        preview_win.transient(root)
        preview_win.grab_set()

        tk.Label(preview_win, text="Edit and Confirm Email", font=("Segoe UI", 14, "bold"), bg="#ffffff", pady=10).pack()

        preview_text = tk.Text(preview_win, wrap="word", font=("Segoe UI", 10), bg="#f8f9fa", bd=1, relief="solid", height=18)
        preview_text.insert(tk.END, generated_email)
        preview_text.pack(padx=20, pady=(5, 10), fill="both", expand=True)

        btn_frame = tk.Frame(preview_win, bg="#ffffff")
        btn_frame.pack(pady=10)

        def confirm_and_send():
            edited_content = preview_text.get("1.0", tk.END).strip()
            if not edited_content:
                messagebox.showerror("❌ Error", "Email content cannot be empty.")
                return
            send_email(recipient_email, subject, edited_content, attachment_file_path)
            preview_win.destroy()

        tk.Button(btn_frame, text="✅ Send Email", bg="#198754", fg="white", font=("Segoe UI", 10, "bold"), activebackground="#157347", width=14, command=confirm_and_send).grid(row=0, column=0, padx=10)
        tk.Button(btn_frame, text="❌ Cancel", bg="#6c757d", fg="white", font=("Segoe UI", 10, "bold"), activebackground="#5a6268", width=14, command=preview_win.destroy).grid(row=0, column=1, padx=10)

        preview_win.focus()

    except Exception as e:
        messagebox.showerror("❌ Error", f"Failed to generate or send email:\n{str(e)}")

# ==== UI Setup ====
root = tk.Tk()
root.title("📨 AI Gmail Assistant")
root.geometry("650x600")
root.configure(bg="#e9ecef")
root.resizable(False, False)

card = tk.Frame(root, bg="#ffffff", bd=0, highlightbackground="#ced4da", highlightthickness=1)
card.place(relx=0.5, rely=0.5, anchor="center", width=610, height=580)

header = tk.Label(card, text="LangChain Gmail Assistant", font=("Segoe UI", 18, "bold"), bg="#212529", fg="#ffffff", pady=15)
header.pack(fill="x")

form_area = tk.Frame(card, bg="#ffffff", padx=20, pady=20)
form_area.pack(fill="both", expand=True)

def add_labeled_entry(label_text):
    lbl = tk.Label(form_area, text=label_text, font=("Segoe UI", 11, "bold"), bg="#ffffff", fg="#343a40")
    lbl.pack(anchor="w", pady=(12, 2))
    entry = tk.Entry(form_area, font=("Segoe UI", 11), bd=1, relief="solid", highlightthickness=1, highlightcolor="#6c757d")
    entry.pack(fill="x", pady=(0, 5))
    return entry

recipient_entry = add_labeled_entry("Recipient Email")
subject_entry = add_labeled_entry("Subject")

tk.Label(form_area, text="Details", font=("Segoe UI", 11, "bold"), bg="#ffffff", fg="#343a40").pack(anchor="w", pady=(12, 2))
details_text = tk.Text(form_area, height=5, font=("Segoe UI", 10), bd=1, relief="solid", wrap="word", highlightthickness=1, highlightcolor="#6c757d")
details_text.pack(fill="both", expand=True, pady=(0, 10))

attach_frame = tk.Frame(form_area, bg="#ffffff")
attach_frame.pack(fill="x", pady=(5, 10))
tk.Button(attach_frame, text="📎 Attach File", font=("Segoe UI", 10, "bold"), bg="#0d6efd", fg="white", command=browse_attachment).pack(side="left", padx=(0, 10))
attachment_label = tk.Label(attach_frame, text="No file attached", bg="#ffffff", fg="#6c757d", font=("Segoe UI", 10))
attachment_label.pack(side="left")

btn_frame = tk.Frame(form_area, bg="#ffffff")
btn_frame.pack(pady=(10, 0))

def create_button(parent, text, bg, fg, hover_bg, command):
    btn = tk.Button(parent, text=text, bg=bg, fg=fg, font=("Segoe UI", 11, "bold"), activebackground=hover_bg, activeforeground=fg, width=14, bd=0, pady=7, relief="flat", command=command)
    def on_enter(e): btn.config(bg=hover_bg)
    def on_leave(e): btn.config(bg=bg)
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn

create_button(btn_frame, "Generate & Send", "#198754", "white", "#157347", generate_and_send_email).grid(row=0, column=0, padx=5)
create_button(btn_frame, "Clear", "#ffc107", "black", "#e0a800", lambda: [recipient_entry.delete(0, tk.END), subject_entry.delete(0, tk.END), details_text.delete("1.0", tk.END), attachment_label.config(text="No file attached", fg="#6c757d")]).grid(row=0, column=1, padx=5)
create_button(btn_frame, "Exit", "#dc3545", "white", "#bb2d3b", root.quit).grid(row=0, column=2, padx=5)

root.mainloop()

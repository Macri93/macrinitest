import re
import time
import smtplib
import threading
import dash
import pandas as pd
from dash import dcc, html
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configurazione
LOG_FILE = "syslog.txt"
PATTERN_ALERT = "failed login|error|intrusion detected"
ALERTS = []

# Funzione per analizzare i log
class LogHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == LOG_FILE:
            with open(LOG_FILE, "r") as file:
                for line in file:
                    if re.search(PATTERN_ALERT, line, re.IGNORECASE):
                        ALERTS.append({"Evento": line.strip(), "Timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "Gravità": "Alta"})
                        print(f"⚠️ ALERT: {line.strip()}")
                        send_email_alert(line.strip())

# Funzione per inviare email
def send_email_alert(message):
    try:
        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login("tuo_email@example.com", "password")
        server.sendmail("tuo_email@example.com", "admin@example.com", f"ALERT: {message}")
        server.quit()
        print("📩 Email di alert inviata con successo!")
    except Exception as e:
        print(f"❌ Errore nell'invio email: {e}")

# Monitoraggio log
observer = Observer()
observer.schedule(LogHandler(), path=".", recursive=False)
observer.start()

# Creazione dashboard con Dash
app = dash.Dash(__name__)

def generate_table():
    df = pd.DataFrame(ALERTS)
    return html.Table([
        html.Tr([html.Th(col) for col in df.columns])] +
        [html.Tr([html.Td(df.iloc[i][col]) for col in df.columns]) for i in range(len(df))]
    ) if not df.empty else html.P("✅ Nessun alert rilevato.")

app.layout = html.Div([
    html.H1("MACRINI TEST Dashboard"),
    dcc.Graph(figure={"data": [{"x": [a["Timestamp"] for a in ALERTS], "y": [a["Gravità"] for a in ALERTS], "type": "bar"}]}),
    generate_table()
])

if __name__ == "__main__":
    print("🔍 Monitoraggio log attivo...")
    observer_thread = threading.Thread(target=lambda: observer.join())
    observer_thread.start()
    app.run(debug=True)

"""Demo UI (fixture)."""
import gradio as gr


def respond(message, history):
    return "hello"


demo = gr.ChatInterface(respond)

if __name__ == "__main__":
    demo.launch(share=True)

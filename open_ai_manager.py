from openai import OpenAI
import os
      

class chatManager:
    
    def __init__(self, model):
        self.model = model
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))


    # Asks a question with no chat history
    def chat(self, prompt=""):
        chat_question = [{"role": "user", "content": prompt}]

        completion = self.client.chat.completions.create(
          model=self.model,
          messages=chat_question
        )

        openai_answer = completion.choices[0].message.content
        return openai_answer


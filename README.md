# **Servidor de Nuvem Segura com Criptografia e 2FA**

Este projeto é uma implementação em Python de um sistema cliente-servidor que simula um serviço de armazenamento em nuvem seguro, baseado na especificação da tarefa prática de INE5680.  

## **Tecnologias Utilizadas**

* **Linguagem:** Python 3  
* **Servidor:** Flask  
* **Comunicação:** API REST (HTTP)  
* **Bibliotecas Criptográficas:**  
  * cryptography: Para derivação de chaves (PBKDF2), sais e cifragem autenticada (AES-GCM).  
  * hashlib: Para derivação de chave no servidor (Scrypt).  
* **Autenticação 2FA:**  
  * pyotp: Para geração e validação de códigos TOTP.  
  * qrcode\[pil\]: Para gerar o QR Code de configuração do 2FA.  
* **Cliente HTTP:** requests

## **Recursos Implementados**

* **Autenticação Segura:** Um processo de autenticação robusto que utiliza PBKDF2 no cliente e Scrypt no servidor, garantindo que a senha do usuário nunca seja transmitida diretamente.  
* **Autenticação de Dois Fatores (2FA):** Após o registro, um QR Code é gerado para configuração em aplicativos como Google Authenticator ou Authy. O login requer a senha e um código TOTP válido.  
* **Criptografia de Arquivos:** Os arquivos são cifrados no cliente usando **AES-GCM** (criptografia autenticada) antes de serem enviados ao servidor. A chave de cifragem é derivada da senha do usuário em tempo de execução e nunca é armazenada.  
* **Privacidade Total:** O servidor armazena apenas os dados cifrados, não tendo conhecimento do conteúdo dos arquivos ou das chaves de decifragem.

## **Como Executar**

A aplicação possui uma arquitetura cliente-servidor e, portanto, precisa ser executada em dois terminais separados.

### **Pré-requisitos**

* Python 3\.  
* Um aplicativo autenticador no seu celular (ex: Google Authenticator, Authy).

### **Passos para Execução**

1. Salvar os Arquivos:  
   Certifique-se de que os seguintes arquivos estejam no mesmo diretório:  
   * server.py  
   * client.py  
   * crypto_utils.py  
   * install_dependencies.sh  
2. Instalar Dependências:  
   Abra um terminal no diretório do projeto e execute o script de instalação:  
   bash ./install_dependencies.sh

3. Iniciar o Servidor:  
   No mesmo terminal, inicie o servidor. Ele ficará aguardando as requisições do cliente.  
   python3 server.py

   Você verá uma mensagem indicando que o servidor está online. Deixe este terminal aberto.  
4. Iniciar o Cliente:  
   Abra um novo terminal. Navegue até o mesmo diretório e inicie a aplicação cliente.  
   python3 client.py

   Agora você pode interagir com o sistema através deste segundo terminal.

## **Fluxo de Uso e Transferência de Arquivos**

Siga os passos abaixo para testar todas as funcionalidades.

### **1\. Registro de um Novo Usuário**

* No cliente, escolha a opção **1\. registrar**.  
* Digite um nome de usuário e uma senha.  
* Um **QR Code** será exibido no terminal. Use seu aplicativo autenticador (Google Authenticator, etc.) para escaneá-lo. Isso adicionará sua conta ao aplicativo.

### **2\. Login**

* No cliente, escolha a opção **2\. login**.  
* Digite seu nome de usuário e senha.  
* O sistema solicitará o código de 6 dígitos que aparece no seu aplicativo autenticador. Digite-o para completar o login.
# Sala de Bate-Papo Simples com Soquetes e Chaves Assimétricas

Este é um projeto de sala de bate-papo simples que utiliza soquetes (sockets) para comunicação entre um servidor e vários clientes. O projeto também incorpora criptografia de chaves assimétricas para garantir a segurança da comunicação.

## Descrição do Projeto

O projeto consiste em duas partes principais: o código do cliente e o código do serviço (servidor). Aqui está uma visão geral das funcionalidades e estrutura do projeto:

### Código do Cliente

O código do cliente é responsável por:

- Gerar um par de chaves público e privado.
- Estabelecer uma conexão com o servidor.
- Enviar a chave pública para o servidor.
- Autenticar-se com um nome de usuário e senha.
- Receber um token de autenticação do servidor.
- Enviar e receber mensagens criptografadas para e do servidor.

### Código do Serviço (Servidor)

O código do serviço (servidor) é responsável por:

- Iniciar um servidor que escuta por conexões de clientes.
- Receber as chaves públicas dos clientes.
- Autenticar os clientes com base em nome de usuário e senha.
- Gerar um token de autenticação para os clientes autenticados.
- Encaminhar mensagens criptografadas para todos os clientes conectados.

### Principais Recursos

- Comunicação Cliente-Servidor: Através de soquetes, os clientes podem se conectar ao servidor para enviar e receber mensagens.
- Autenticação: Os clientes devem fornecer um nome de usuário e senha para se autenticarem com o servidor.
- Criptografia: A comunicação entre clientes e servidor é criptografada usando chaves assimétricas para garantir a segurança.
- Token de Autenticação: Após a autenticação bem-sucedida, os clientes recebem um token de autenticação que é usado para identificá-los.
- Interface de Linha de Comando (CLI): Os clientes interagem com o programa através de comandos inseridos na linha de comando.

## Configuração

Para executar o projeto, siga as etapas abaixo:

1. Certifique-se de que o Python esteja instalado em seu sistema.
2. Instale as dependências necessárias executando o comando `pip install cryptography jwt`.
3. Execute o código do servidor em um terminal com o comando `python server.py`.
4. Execute o código do cliente em terminais separados com o comando `python client.py`.

## Funcionamento

Após a configuração, os clientes podem se conectar ao servidor, autenticar-se e começar a trocar mensagens. A comunicação é criptografada para garantir a privacidade e a segurança das mensagens.

## Contribuições

Contribuições para melhorias e novos recursos são bem-vindas! Sinta-se à vontade para abrir uma issue ou criar um pull request.

## Autor

Este projeto foi desenvolvido por [Davio27] e está disponível sob a licença [Licença MIT].

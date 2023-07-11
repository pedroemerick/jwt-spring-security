https://www.toptal.com/spring/spring-security-tutorial

Dependencia do spring seurity:

`<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>`

Ao adicionar a dependencia a aplicação já começa a cobrar a autenticação 
para acessar os endpoints, já retornando um 401 nas chamadas.

Quando inicia a aplicação, o spring já gera uma senha para o usuário padrão
'user' do spring security. Essa senha pode ser encontrada no log da aplicação, como:

`Using generated security password: 7c2a0674-5c47-4a8b-bb78-089a271c1ae0`

O spring security já cria as rotas de login e logout, gerando até mesmo uma
página web para isso.


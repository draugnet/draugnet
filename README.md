### Early builds of Abracadabra, the (anonymous) cybersecurity submission tool.

- The intent of the application is to act as an entry point into sharing communities / reporting portal for CSIRTs
- No prior contact is required, the tool allows for anonymous submissions to MISP
- Users of the tool will receive tokens for each submission that they can use to keep track of the evolution of their reports

- This is the back-end of the application, with the frontend being found here:


```mermaid
---
config:
      theme: redux
---
flowchart 
  U([fa:fa-user User])
  U --> |fa:fa-window-maximize GUI| A(["Abracadabra front-end"])
  A --> |fa:fa-code API| B["Abracadabra back-end"]
  B --> |Token:UUID tuples| R[fa:fa-database Redis]
  B --> |fa:fa-code anon API account| C[fa:fa-comments MISP]
  U --> |fa:fa-code API| B
  B --> |generates| T[fa:fa-tag Token]
  T --> |Responds with| U
  CS[fa:fa-users CSIRT]
  C <--> CS
```

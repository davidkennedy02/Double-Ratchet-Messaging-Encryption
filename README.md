"The Double Ratchet algorithm is used by two parties to exchange encrypted messages based on a shared secret key. Typically the parties will use some key agreement protocol (such as X3DH [1]) to agree on the shared secret key. 
Following this, the parties will use the Double Ratchet to send and receive encrypted messages. The parties derive new keys for every Double Ratchet message so that earlier keys cannot be calculated from later ones. The parties also 
send Diffie-Hellman public values attached to their messages. The results of Diffie-Hellman calculations are mixed into the derived keys so that later keys cannot be calculated from earlier ones. These properties gives some protection to 
earlier or later encrypted messages in case of a compromise of a party's keys." 

Read more of the Signal Double Ratchet specification [here](https://signal.org/docs/specifications/doubleratchet/)

Read my report regarding my implementation of their algorithm [here](report.pdf)


Notes for running the program: 

- To run the system, first install any dependencies using "pip install -r /requirements.txt"

- Append the extension '.pem' to the files 'servercert' and 'serverkey'

- Configure the connection details within the 'db_model.py' file, allowing connection to your MySQL database
    - The installation and setup of MySQL is left to the user 

- Then run the server, followed by an instance of 'new_client.py'

- To create a user, follow the instructions 
- Similarly with logging in

- To create a group, make sure you invite a member that exists! 

- To refresh the state of the chat, hit enter - this will process any sent messages that haven't shown up 

- To exit the group, write "/quit" and hit enter 

- To add a user to a group, write "/invite" in the group and hit enter 
    - You will be asked for the user's name - make sure they exist!

- Please be careful to log out before exiting the terminal :) 

- To return the database to it's initial state, log into the MYSQL database
    - Simply drop all tables within the database

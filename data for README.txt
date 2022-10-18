The tool GUI interface build up brief:

The tool GUI interface has been generated using tkinter library which helps in generating a tool window. It provides us with options to create labels, text entry boxes, check-boxes and much more (there is no end for creativity) It is also possible to attach jpg/png files to the tool using PIL library.There are many other toos/packages for building GUI in python like PyQt5, WxPython and Kivy however we have used tKinter owing to its simplicity in usage and because the focus was more on attaching the data fetching code to be attached easily for execution and displaying output.However this does not mean other tools are complex, its just that we have used tKinter.
The overall build is pretty simple:
1. The framework/GUI window was generated to get the initial look and feel.
2. Relevant labels, text entry boxes and checkboxes were created
3. The functions created were attached to the labels and text entry and output code to the display area
4. All functioning of the code and output was checked
5. Code was further adjusted a few times for specific presentation style on the output area
6. Tool cosmetics were further refined by adjusting placements of each element
7. Tool title logo file), tool trademark logo were inserted using appropiate code lines

*******************************************************************************************************

The two repositories are sublist3r and builtwith however python libraries were available for both of these repos so I used those. I have provided a brief of the library/package used for each parameter or identifier in the tool code.

Repos/Libraries for the tool options

1. Domain registration details: Python package "whois"

2. Subdomains and Open ports: python package "sublist3r" for enumerating subdomains and ports.
   Tweaked the code a little for displaying the subdomains and ports together.

3. Web Technologies on the domain: python package "builtwith" along with combination of web scraping using "request package", to concatenate details obtained via builtwith and request package and present a combination data.

4. Email breach details: Entirely web scraping using 
   i) find element/XPATH method
  ii) beautifulsoup package

5. Documents hosted on domain: Web scraping by engaging pyautogui for mouse movement automation and
   then use "OS" package to read file path and return output


References:

*******************************************************************************************

OSINT for Security: 

Ziółkowska, A. (2018). Open source intelligence (OSINT) as an element of military recon. Security and Defence Quarterly, 19(2), pp.65-77. https://doi.org/10.5604/01.3001.0012.1474

Akhgar, B., 2016. Osint as an integral part of the national security apparatus. In Open Source Intelligence Investigation (pp. 3-9). Springer, Cham.


********************************************************************************************

OSINT for economic development:

Wanigasinghe SL. OPEN SOURCE INTELLIGENCE MODEL FOR ENHANCING THE NATIONAL INTELLIGENCE CAPABILITY OF SRI LANKA. CORE VALUES.:88.

********************************************************************************************

OSINT for sentinment analysis:

Garzia, F., Cusani, R., Borghini, F., Saltini, B., Lombardi, M. and Ramalingam, S., 2018, October. Perceived risk assessment through open-source intelligent techniques for opinion mining and sentiment analysis: The case study of the Papal Basilica and Sacred Convent of Saint Francis in Assisi, Italy. In 2018 International Carnahan Conference on Security Technology (ICCST) (pp. 1-5). IEEE.

Mediná, M.J.H., Hernández, C.C.P., López, D.O.D., Ruiz, J.C.G. and Rico, R.A.P., 2018. Open source intelligence (osint) in a colombian context and sentiment analysys. Revista Vínculos: Ciencia, tecnología y sociedad, 15(2), pp.195-214.

******************************************************************************************

OSINT for Web scraper tools:

Sonawane, H.S., Deshmukh, S., Joy, V. and Hadsul, D., 2022, June. Torsion: Web Reconnaissance using Open Source Intelligence. In 2022 2nd International Conference on Intelligent Technologies (CONIT) (pp. 1-4). IEEE.

Magalhães, A. and Magalhães, J.P., 2018, June. TExtractor: An OSINT Tool to Extract and Analyse Audio/Video Content. In International Conference on Innovation, Engineering and Entrepreneurship (pp. 3-9). Springer, Cham.

Anand V, A. and Mohan, A.K., 2020. PeopleXploit--A hybrid tool to collect public data. arXiv preprint arXiv:2010.15668.

********************************************************************************

Others:

OSINT for competitive intelligence:
Primc, Ž., 2021. The Use of Tools for Obtaining Data From Publicly Accessible Sources for the Purpose of Competitive Intelligence in Enterprises. Varstvoslovje, 23(4), pp.425-446.

Monterrubio, S.M.M., Noain-Sánchez, A., Pérez, E.V. and Crespo, R.G., 2021. Coronavirus fake news detection via MedOSINT check in health care official bulletins with CBR explanation: The way to find the real information source through OSINT, the verifier tool for official journals. Information Sciences, 574, pp.210-237.



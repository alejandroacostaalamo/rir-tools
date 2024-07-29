# El objetivo de este script es parsear un archivo "show ip bgp" o "
# "show bgp ipv6"
# y como resultado deja en un diccionario lo siguiente: bgp_dict[PREFIX]=["AS_PATH1","AS_PATH2"]

#Some variable declaration
file_path = 'tablav6-corta.txt'

def parse_bgp_table(file_path):
    #Esta funcion recibe la ubicacion de un archivo de texto al estilo show ip bgp
    #devuelve un diccionario con los prefijos y los AS_PATH
    #el dict que devuelve es tipo bgp_dict[PREFIX]=["AS_PATH1","AS_PATH2"]
    bgp_dict = {}  #tabla bgp_dict completamente vacia
    current_prefix = None #comenzando no hay ningun prefijo analizando
    PREVIOUSPREFIX=''  #reiniciamos la variable

    with open(file_path, 'r') as file:
        for line in file: #leemos el archivo linea por linea
            # Remove leading and trailing whitespace
            #line = line.strip()
                    
            # Skip header lines or empty lines
            if not line or line.startswith('BGP table') or line.startswith('Status codes') or line.startswith('Origin codes') or line.startswith('Network'):
                continue

            #print ('Procesando: ',line) #Uncomment for debugging

            if (line): #que la linea no este vacia
              if line[0]=="*": #Lines with prefix always begin with a * (but some lines have * an no prefix)
                 b=line[3::] #in the show ip bgp, the prefix always begin in the position 3+
                 PREFIX=b.split(' ')[0].strip() 
                 if len(PREFIX) < 4: #in case prefix is empty is means this is another as_path but the same previous prefix
                   #print ('prefijo muy corto {} usando PREVIOUSPREFIX {}'.format(PREFIX,PREVIOUSPREFIX ))
                   PREFIX=PREVIOUSPREFIX #esta linea no especifica prefijo, usando el previo
              else:
                PREFIX=PREVIOUSPREFIX  #esta linea no especifica prefijo, usando el previo
       
            try:  #just trying to prevent line[59] does not return "out of range" or something like that
              if (line[59]) == "0":  #El weight en el archivo de potaroo siempre es 0 y esta en la posicion 59
                AS_PATH=line[61:-2].strip()  #Aqui se toma todo el AS_PATH  
                if PREFIX and AS_PATH:  #Before adding this to the dict, just want to be sure no empty variables are there
                 if PREFIX not in bgp_dict: #si es la primera vez que procesamos este prefijo
                    bgp_dict[PREFIX]=[AS_PATH]
                 else:  #ya este prefijo lo habiamos procesado
                    bgp_dict[PREFIX].append(AS_PATH)

            except Exception:
               pass
        
            PREVIOUSPREFIX=PREFIX  #dejamos esta variable en caso de que la siguiente linea no tenga prefijo especificado
    
    return bgp_dict

# Parse the BGP table and store the result in a dictionary
# Aquí recorremos el archivo especificado arriba y procesamos la tabla BGP. Lo importante son los 
# diccionarios resultantes como lac_bgp_table_dict
bgp_table_dict = parse_bgp_table(file_path)  #  en bgp_table_dict queda la tabla medio cruda, aun falta limpiarla mas

for prefix, as_paths in bgp_table_dict.items():
    if len(as_paths)==1:
      for as_path in as_paths:
        print(f"{prefix}:")   
        print ('  ',as_path)

